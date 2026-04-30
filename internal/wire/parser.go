// Copyright 2026 Jonathan Gonzalez V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	maxBufferedBytes   = 1 << 20
	maxMessageLength   = 64 << 20
	resyncRetainBytes  = 64
	DefaultDetailLimit = 4096

	protocolVersion30 = 196608
	cancelRequestCode = 80877102
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
)

type Session struct {
	User        string
	Database    string
	Application string
	Replication bool
}

type Event struct {
	OccurredAt  time.Time
	PID         uint32
	TID         uint32
	CgroupID    uint64
	ConnPtr     uint64
	Comm        string
	Direction   Direction
	API         API
	MessageType string
	MessageCode byte
	MessageLen  int
	Truncated   bool
	Group       ContentGroup
	Session     Session
	Summary     string
	SQL         string
}

type connectionKey struct {
	pid     uint32
	connPtr uint64
}

type streamKey struct {
	connectionKey
	direction Direction
}

type connectionState struct {
	session              Session
	startupSeen          bool
	currentGroup         ContentGroup
	copyGroup            ContentGroup
	replicationRequested bool
	walDecoder           *walStreamDecoder
}

type streamState struct {
	buffer      []byte
	startupDone bool
	syncLost    bool
}

type Parser struct {
	connections  map[connectionKey]*connectionState
	streams      map[streamKey]*streamState
	previewLimit int
}

func NewParser(previewLimit int) *Parser {
	if previewLimit < 0 {
		previewLimit = DefaultDetailLimit
	}

	return &Parser{
		connections:  make(map[connectionKey]*connectionState),
		streams:      make(map[streamKey]*streamState),
		previewLimit: previewLimit,
	}
}

func (p *Parser) Feed(chunk Chunk) []Event {
	connKey := connectionKey{pid: chunk.PID, connPtr: chunk.ConnPtr}
	conn := p.connections[connKey]
	if conn == nil {
		conn = &connectionState{}
		p.connections[connKey] = conn
	}

	sKey := streamKey{
		connectionKey: connKey,
		direction:     chunk.Direction,
	}
	stream := p.streams[sKey]
	if stream == nil {
		stream = &streamState{
			startupDone: chunk.Direction == DirectionServerToClient || conn.startupSeen,
		}
		p.streams[sKey] = stream
	}

	stream.buffer = append(stream.buffer, chunk.Data...)
	if len(stream.buffer) > maxBufferedBytes {
		stream.buffer = nil
		stream.syncLost = true
		event := newEvent(chunk, conn.session, "BUFFER_RESET", 0, 0, false, "parser buffer exceeded 1048576 bytes; resync required", "")
		event.Group = activeGroup(conn)
		return []Event{event}
	}

	if stream.syncLost {
		p.tryResync(stream, chunk.Direction)
	}

	events := p.parseBuffered(chunk, conn, stream)

	if chunk.Truncated {
		events = append(events, p.decodeTruncatedEvent(chunk, conn, stream))
		stream.buffer = nil
		stream.syncLost = true
	}

	return events
}

func (p *Parser) parseBuffered(chunk Chunk, conn *connectionState, stream *streamState) []Event {
	var events []Event

	for {
		if chunk.Direction == DirectionClientToServer && !stream.startupDone {
			if len(stream.buffer) < 4 {
				return events
			}

			length := int(binary.BigEndian.Uint32(stream.buffer[:4]))
			if length < 8 || length > maxMessageLength {
				stream.syncLost = true
				p.tryResync(stream, chunk.Direction)
				if stream.syncLost {
					stream.buffer = nil
					event := newEvent(chunk, conn.session, "PARSE_ERROR", 0, 0, false, fmt.Sprintf("invalid startup packet length=%d", length), "")
					event.Group = GroupConnectionConfig
					return append(events, event)
				}
				continue
			}
			if len(stream.buffer) < length {
				return events
			}

			packet := append([]byte(nil), stream.buffer[:length]...)
			stream.buffer = stream.buffer[length:]
			stream.startupDone = true
			conn.startupSeen = true
			event, session := parseStartupPacket(chunk, packet, p.previewLimit)
			conn.session = session
			event.Session = session
			p.applyStartupState(conn, &event)
			events = append(events, event)
			continue
		}

		if len(stream.buffer) < 5 {
			return events
		}

		code := stream.buffer[0]
		length := int(binary.BigEndian.Uint32(stream.buffer[1:5]))
		if length < 4 || length > maxMessageLength {
			stream.syncLost = true
			p.tryResync(stream, chunk.Direction)
			if stream.syncLost {
				stream.buffer = nil
				event := newEvent(chunk, conn.session, "PARSE_ERROR", code, 0, false, fmt.Sprintf("invalid message length=%d code=%s", length, formatCode(code)), "")
				event.Group = activeGroup(conn)
				return append(events, event)
			}
			continue
		}

		total := 1 + length
		if len(stream.buffer) < total {
			return events
		}

		payload := append([]byte(nil), stream.buffer[5:total]...)
		stream.buffer = stream.buffer[total:]

		var event Event
		if chunk.Direction == DirectionClientToServer {
			event = parseClientMessage(chunk, conn.session, code, payload, p.previewLimit)
			p.applyClientEventState(conn, &event)
		} else {
			event = parseServerMessage(chunk, conn.session, code, payload, p.previewLimit)
			p.enrichServerEvent(conn, &event, payload, false, 0)
			p.applyServerEventState(conn, &event)
		}
		events = append(events, event)
	}
}

func (p *Parser) tryResync(stream *streamState, direction Direction) {
	if !stream.syncLost {
		return
	}

	if direction == DirectionClientToServer && !stream.startupDone {
		if len(stream.buffer) >= 4 {
			length := int(binary.BigEndian.Uint32(stream.buffer[:4]))
			if length >= 8 && length <= len(stream.buffer) && length <= maxMessageLength {
				stream.syncLost = false
				return
			}
		}
	}

	if idx := findRegularMessageStart(stream.buffer, direction); idx >= 0 {
		stream.buffer = stream.buffer[idx:]
		stream.startupDone = true
		stream.syncLost = false
		return
	}

	if len(stream.buffer) > resyncRetainBytes {
		stream.buffer = append([]byte(nil), stream.buffer[len(stream.buffer)-resyncRetainBytes:]...)
	}
}

func parseStartupPacket(chunk Chunk, packet []byte, previewLimit int) (Event, Session) {
	if len(packet) < 8 {
		return newEvent(chunk, Session{}, "Startup", 0, len(packet), false, "short startup packet", ""), Session{}
	}

	code := binary.BigEndian.Uint32(packet[4:8])
	switch code {
	case sslRequestCode:
		return newEvent(chunk, Session{}, "SSLRequest", 0, len(packet), false, "startup SSLRequest", ""), Session{}
	case gssEncRequestCode:
		return newEvent(chunk, Session{}, "GSSENCRequest", 0, len(packet), false, "startup GSSENCRequest", ""), Session{}
	case cancelRequestCode:
		return newEvent(chunk, Session{}, "CancelRequest", 0, len(packet), false, "startup CancelRequest", ""), Session{}
	}

	session := Session{}
	if code == protocolVersion30 {
		params := parseStartupParameters(packet[8:])
		session.User = params["user"]
		session.Database = params["database"]
		session.Application = params["application_name"]
		session.Replication = isReplicationStartup(params["replication"])
	}

	summary := fmt.Sprintf("protocol=%d.%d", code>>16, code&0xffff)
	if session.User != "" {
		summary += fmt.Sprintf(" user=%s", session.User)
	}
	if session.Database != "" {
		summary += fmt.Sprintf(" db=%s", session.Database)
	}
	if session.Application != "" {
		summary += fmt.Sprintf(" app=%s", session.Application)
	}
	if options := parseStartupParameters(packet[8:])["options"]; options != "" {
		summary += fmt.Sprintf(" options=%s", previewString(options, previewLimit))
	}

	return newEvent(chunk, session, "Startup", 0, len(packet), false, summary, ""), session
}

func parseStartupParameters(payload []byte) map[string]string {
	params := make(map[string]string)
	offset := 0
	for offset < len(payload) {
		key, next, ok := readCString(payload, offset)
		if !ok {
			break
		}
		offset = next
		if key == "" {
			break
		}
		value, next, ok := readCString(payload, offset)
		if !ok {
			break
		}
		offset = next
		params[key] = value
	}
	return params
}

func parseClientMessage(chunk Chunk, session Session, code byte, payload []byte, previewLimit int) Event {
	switch code {
	case 'Q':
		sql, _, _ := readCString(payload, 0)
		return newEvent(chunk, session, "Query", code, len(payload)+5, false, fmt.Sprintf("query=%s", previewString(sql, previewLimit)), sql)
	case 'P':
		statement, next, ok := readCString(payload, 0)
		if !ok {
			return newEvent(chunk, session, "Parse", code, len(payload)+5, false, "parse message truncated", "")
		}
		sql, _, _ := readCString(payload, next)
		return newEvent(chunk, session, "Parse", code, len(payload)+5, false, fmt.Sprintf("statement=%s sql=%s", emptyLabel(statement, "<unnamed>"), previewString(sql, previewLimit)), sql)
	case 'B':
		portal, next, ok := readCString(payload, 0)
		if !ok {
			return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind message truncated", "")
		}
		statement, next, ok := readCString(payload, next)
		if !ok {
			return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind message truncated", "")
		}
		paramFormatCount, next, ok := readInt16(payload, next)
		if !ok {
			return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind message truncated", "")
		}
		next += int(paramFormatCount) * 2
		paramCount, next, ok := readInt16(payload, next)
		if !ok {
			return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind message truncated", "")
		}
		totalBytes := 0
		for i := 0; i < int(paramCount); i++ {
			paramLen, nextOffset, ok := readInt32(payload, next)
			if !ok {
				return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind parameter list truncated", "")
			}
			next = nextOffset
			if paramLen >= 0 {
				next += int(paramLen)
				totalBytes += int(paramLen)
			}
			if next > len(payload) {
				return newEvent(chunk, session, "Bind", code, len(payload)+5, false, "bind parameter payload truncated", "")
			}
		}
		return newEvent(chunk, session, "Bind", code, len(payload)+5, false, fmt.Sprintf("portal=%s statement=%s params=%d param_bytes=%d formats=%d", emptyLabel(portal, "<unnamed>"), emptyLabel(statement, "<unnamed>"), paramCount, totalBytes, paramFormatCount), "")
	case 'D':
		if len(payload) == 0 {
			return newEvent(chunk, session, "Describe", code, len(payload)+5, false, "describe message missing target", "")
		}
		name, _, _ := readCString(payload, 1)
		target := "statement"
		if payload[0] == 'P' {
			target = "portal"
		}
		return newEvent(chunk, session, "Describe", code, len(payload)+5, false, fmt.Sprintf("target=%s name=%s", target, emptyLabel(name, "<unnamed>")), "")
	case 'E':
		portal, next, ok := readCString(payload, 0)
		if !ok {
			return newEvent(chunk, session, "Execute", code, len(payload)+5, false, "execute message truncated", "")
		}
		maxRows, _, ok := readInt32(payload, next)
		if !ok {
			return newEvent(chunk, session, "Execute", code, len(payload)+5, false, "execute message truncated", "")
		}
		return newEvent(chunk, session, "Execute", code, len(payload)+5, false, fmt.Sprintf("portal=%s max_rows=%d", emptyLabel(portal, "<unnamed>"), maxRows), "")
	case 'C':
		if len(payload) == 0 {
			return newEvent(chunk, session, "Close", code, len(payload)+5, false, "close message missing target", "")
		}
		name, _, _ := readCString(payload, 1)
		target := "statement"
		if payload[0] == 'P' {
			target = "portal"
		}
		return newEvent(chunk, session, "Close", code, len(payload)+5, false, fmt.Sprintf("target=%s name=%s", target, emptyLabel(name, "<unnamed>")), "")
	case 'H':
		return newEvent(chunk, session, "Flush", code, len(payload)+5, false, "flush", "")
	case 'S':
		return newEvent(chunk, session, "Sync", code, len(payload)+5, false, "sync", "")
	case 'X':
		return newEvent(chunk, session, "Terminate", code, len(payload)+5, false, "terminate", "")
	case 'p':
		return newEvent(chunk, session, "PasswordMessage", code, len(payload)+5, false, fmt.Sprintf("password payload redacted len=%d", len(payload)), "")
	case 'f':
		reason, _, _ := readCString(payload, 0)
		return newEvent(chunk, session, "CopyFail", code, len(payload)+5, false, fmt.Sprintf("reason=%s", previewString(reason, previewLimit)), "")
	case 'd':
		return parseClientCopyData(chunk, session, code, payload, previewLimit)
	case 'c':
		return newEvent(chunk, session, "CopyDone", code, len(payload)+5, false, "copy done", "")
	default:
		return newEvent(chunk, session, clientMessageName(code), code, len(payload)+5, false, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit)), "")
	}
}

func parseServerMessage(chunk Chunk, session Session, code byte, payload []byte, previewLimit int) Event {
	switch code {
	case 'R':
		authCode, _, ok := readInt32(payload, 0)
		if !ok {
			return newEvent(chunk, session, "Authentication", code, len(payload)+5, false, "authentication message truncated", "")
		}
		summary := fmt.Sprintf("auth=%s", authTypeName(authCode))
		if authCode == 10 {
			summary += fmt.Sprintf(" mechanisms=%s", saslMechanisms(payload[4:]))
		}
		return newEvent(chunk, session, "Authentication", code, len(payload)+5, false, summary, "")
	case 'S':
		key, next, ok := readCString(payload, 0)
		if !ok {
			return newEvent(chunk, session, "ParameterStatus", code, len(payload)+5, false, "parameter status truncated", "")
		}
		value, _, _ := readCString(payload, next)
		return newEvent(chunk, session, "ParameterStatus", code, len(payload)+5, false, fmt.Sprintf("%s=%s", key, previewString(value, previewLimit)), "")
	case 'K':
		backendPID, next, ok := readInt32(payload, 0)
		if !ok {
			return newEvent(chunk, session, "BackendKeyData", code, len(payload)+5, false, "backend key data truncated", "")
		}
		_, _, ok = readInt32(payload, next)
		if !ok {
			return newEvent(chunk, session, "BackendKeyData", code, len(payload)+5, false, "backend key data truncated", "")
		}
		return newEvent(chunk, session, "BackendKeyData", code, len(payload)+5, false, fmt.Sprintf("backend_pid=%d secret=redacted", backendPID), "")
	case 'Z':
		if len(payload) == 0 {
			return newEvent(chunk, session, "ReadyForQuery", code, len(payload)+5, false, "ready status missing", "")
		}
		return newEvent(chunk, session, "ReadyForQuery", code, len(payload)+5, false, fmt.Sprintf("status=%s", transactionStatus(payload[0])), "")
	case 'T':
		fieldCount, next, ok := readInt16(payload, 0)
		if !ok {
			return newEvent(chunk, session, "RowDescription", code, len(payload)+5, false, "row description truncated", "")
		}
		names := make([]string, 0, min(int(fieldCount), 6))
		for i := 0; i < int(fieldCount); i++ {
			name, nextOffset, ok := readCString(payload, next)
			if !ok {
				break
			}
			next = nextOffset + 18
			if len(names) < 6 {
				names = append(names, name)
			}
			if next > len(payload) {
				break
			}
		}
		summary := fmt.Sprintf("fields=%d", fieldCount)
		if len(names) > 0 {
			summary += fmt.Sprintf(" names=%s", strings.Join(names, ","))
		}
		return newEvent(chunk, session, "RowDescription", code, len(payload)+5, false, summary, "")
	case 'D':
		columnCount, next, ok := readInt16(payload, 0)
		if !ok {
			return newEvent(chunk, session, "DataRow", code, len(payload)+5, false, "data row truncated", "")
		}
		nonNull := 0
		cellBytes := 0
		for i := 0; i < int(columnCount); i++ {
			cellLen, nextOffset, ok := readInt32(payload, next)
			if !ok {
				break
			}
			next = nextOffset
			if cellLen >= 0 {
				nonNull++
				cellBytes += int(cellLen)
				next += int(cellLen)
			}
			if next > len(payload) {
				break
			}
		}
		return newEvent(chunk, session, "DataRow", code, len(payload)+5, false, fmt.Sprintf("columns=%d non_null=%d payload_bytes=%d", columnCount, nonNull, cellBytes), "")
	case 'C':
		tag, _, _ := readCString(payload, 0)
		return newEvent(chunk, session, "CommandComplete", code, len(payload)+5, false, fmt.Sprintf("tag=%s", tag), "")
	case 'E', 'N':
		fields := parseErrorFields(payload)
		kind := "ErrorResponse"
		if code == 'N' {
			kind = "NoticeResponse"
		}
		summary := fmt.Sprintf("severity=%s code=%s message=%s", fields["S"], fields["C"], fields["M"])
		return newEvent(chunk, session, kind, code, len(payload)+5, false, strings.TrimSpace(summary), "")
	case '1':
		return newEvent(chunk, session, "ParseComplete", code, len(payload)+5, false, "parse complete", "")
	case '2':
		return newEvent(chunk, session, "BindComplete", code, len(payload)+5, false, "bind complete", "")
	case '3':
		return newEvent(chunk, session, "CloseComplete", code, len(payload)+5, false, "close complete", "")
	case 'I':
		return newEvent(chunk, session, "EmptyQueryResponse", code, len(payload)+5, false, "empty query response", "")
	case 'n':
		return newEvent(chunk, session, "NoData", code, len(payload)+5, false, "no data", "")
	case 's':
		return newEvent(chunk, session, "PortalSuspended", code, len(payload)+5, false, "portal suspended", "")
	case 'A':
		notifierPID, next, ok := readInt32(payload, 0)
		if !ok {
			return newEvent(chunk, session, "NotificationResponse", code, len(payload)+5, false, "notification truncated", "")
		}
		channel, next, ok := readCString(payload, next)
		if !ok {
			return newEvent(chunk, session, "NotificationResponse", code, len(payload)+5, false, "notification truncated", "")
		}
		payloadText, _, _ := readCString(payload, next)
		return newEvent(chunk, session, "NotificationResponse", code, len(payload)+5, false, fmt.Sprintf("pid=%d channel=%s payload=%s", notifierPID, channel, previewString(payloadText, previewLimit)), "")
	case 't':
		count, _, ok := readInt16(payload, 0)
		if !ok {
			return newEvent(chunk, session, "ParameterDescription", code, len(payload)+5, false, "parameter description truncated", "")
		}
		return newEvent(chunk, session, "ParameterDescription", code, len(payload)+5, false, fmt.Sprintf("parameters=%d", count), "")
	case 'G', 'H', 'W':
		return newEvent(chunk, session, serverMessageName(code), code, len(payload)+5, false, fmt.Sprintf("copy response payload_bytes=%d", len(payload)), "")
	case 'd':
		return parseServerCopyData(chunk, session, code, payload, previewLimit)
	default:
		return newEvent(chunk, session, serverMessageName(code), code, len(payload)+5, false, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit)), "")
	}
}

func parseClientCopyData(chunk Chunk, session Session, code byte, payload []byte, previewLimit int) Event {
	if len(payload) == 0 {
		return newEvent(chunk, session, "CopyData", code, len(payload)+5, false, "copy data bytes=0", "")
	}

	switch payload[0] {
	case 'r':
		if len(payload) < 1+8+8+8+8+1 {
			return newEvent(chunk, session, "StandbyStatusUpdate", code, len(payload)+5, false, "standby status update truncated", "")
		}
		writeLSN, _, _ := readUint64(payload, 1)
		flushLSN, _, _ := readUint64(payload, 9)
		applyLSN, _, _ := readUint64(payload, 17)
		replyRequested := payload[33] == 1
		return newEvent(
			chunk,
			session,
			"StandbyStatusUpdate",
			code,
			len(payload)+5,
			false,
			fmt.Sprintf("write=%s flush=%s apply=%s reply_requested=%t", formatLSN(writeLSN), formatLSN(flushLSN), formatLSN(applyLSN), replyRequested),
			"",
		)
	case 'h':
		if len(payload) < 1+8+4+4+4+4 {
			return newEvent(chunk, session, "HotStandbyFeedback", code, len(payload)+5, false, "hot standby feedback truncated", "")
		}
		xmin, _, _ := readUint32(payload, 9)
		catalogXmin, _, _ := readUint32(payload, 17)
		return newEvent(
			chunk,
			session,
			"HotStandbyFeedback",
			code,
			len(payload)+5,
			false,
			fmt.Sprintf("xmin=%d catalog_xmin=%d", xmin, catalogXmin),
			"",
		)
	default:
		return newEvent(chunk, session, "CopyData", code, len(payload)+5, false, fmt.Sprintf("copy data bytes=%d", len(payload)), "")
	}
}

func parseServerCopyData(chunk Chunk, session Session, code byte, payload []byte, previewLimit int) Event {
	if len(payload) == 0 {
		return newEvent(chunk, session, "CopyData", code, len(payload)+5, false, "copy data bytes=0", "")
	}

	switch payload[0] {
	case 'w':
		if len(payload) < 1+8+8+8 {
			return newEvent(chunk, session, "XLogData", code, len(payload)+5, false, "xlog data truncated", "")
		}
		startLSN, _, _ := readUint64(payload, 1)
		endLSN, _, _ := readUint64(payload, 9)
		walBytes := len(payload) - 25
		if walBytes < 0 {
			walBytes = 0
		}
		return newEvent(
			chunk,
			session,
			"XLogData",
			code,
			len(payload)+5,
			false,
			fmt.Sprintf("wal_start=%s wal_end=%s wal_bytes=%d", formatLSN(startLSN), formatLSN(endLSN), walBytes),
			"",
		)
	case 'k':
		if len(payload) < 1+8+8+1 {
			return newEvent(chunk, session, "PrimaryKeepaliveMessage", code, len(payload)+5, false, "primary keepalive truncated", "")
		}
		endLSN, _, _ := readUint64(payload, 1)
		replyRequested := payload[17] == 1
		return newEvent(
			chunk,
			session,
			"PrimaryKeepaliveMessage",
			code,
			len(payload)+5,
			false,
			fmt.Sprintf("wal_end=%s reply_requested=%t", formatLSN(endLSN), replyRequested),
			"",
		)
	default:
		return newEvent(chunk, session, "CopyData", code, len(payload)+5, false, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit)), "")
	}
}

func (p *Parser) decodeTruncatedEvent(chunk Chunk, conn *connectionState, stream *streamState) Event {
	if event, ok := p.parseTruncatedBufferedMessage(chunk, conn, stream); ok {
		return event
	}

	event := newEvent(
		chunk,
		conn.session,
		"TRUNCATED_CHUNK",
		0,
		int(chunk.TotalLen),
		true,
		fmt.Sprintf("plaintext chunk truncated captured=%d total=%d; parser state reset", chunk.CapturedLen, chunk.TotalLen),
		"",
	)
	event.Group = activeGroup(conn)
	return event
}

func (p *Parser) parseTruncatedBufferedMessage(chunk Chunk, conn *connectionState, stream *streamState) (Event, bool) {
	if chunk.Direction == DirectionClientToServer && !stream.startupDone {
		return Event{}, false
	}
	if len(stream.buffer) < 5 {
		return Event{}, false
	}

	code := stream.buffer[0]
	length := int(binary.BigEndian.Uint32(stream.buffer[1:5]))
	if length < 4 || length > maxMessageLength {
		return Event{}, false
	}

	expectedTotal := 1 + length
	payload := append([]byte(nil), stream.buffer[5:]...)

	var event Event
	if chunk.Direction == DirectionClientToServer {
		event = parseTruncatedClientMessage(chunk, conn.session, code, payload, expectedTotal, p.previewLimit)
	} else {
		event = parseTruncatedServerMessage(chunk, conn.session, code, payload, expectedTotal, p.previewLimit)
		p.enrichServerEvent(conn, &event, payload, true, expectedTotal)
	}
	event.Group = classifyTruncatedEventGroup(conn, event)
	return event, true
}

func parseTruncatedClientMessage(chunk Chunk, session Session, code byte, payload []byte, expectedTotal int, previewLimit int) Event {
	switch code {
	case 'd':
		return parseTruncatedClientCopyData(chunk, session, code, payload, expectedTotal, previewLimit)
	case 'Q':
		sql, _, _ := readCString(payload, 0)
		if sql == "" {
			sql = previewBytes(payload, previewLimit)
		}
		return newEvent(
			chunk,
			session,
			"Query",
			code,
			expectedTotal,
			true,
			truncatedSummary(expectedTotal, len(payload)+5, fmt.Sprintf("query=%s", previewString(sql, previewLimit))),
			sql,
		)
	default:
		return newEvent(
			chunk,
			session,
			clientMessageName(code),
			code,
			expectedTotal,
			true,
			truncatedSummary(expectedTotal, len(payload)+5, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit))),
			"",
		)
	}
}

func parseTruncatedServerMessage(chunk Chunk, session Session, code byte, payload []byte, expectedTotal int, previewLimit int) Event {
	switch code {
	case 'd':
		return parseTruncatedServerCopyData(chunk, session, code, payload, expectedTotal, previewLimit)
	default:
		return newEvent(
			chunk,
			session,
			serverMessageName(code),
			code,
			expectedTotal,
			true,
			truncatedSummary(expectedTotal, len(payload)+5, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit))),
			"",
		)
	}
}

func (p *Parser) enrichServerEvent(conn *connectionState, event *Event, payload []byte, truncated bool, expectedTotal int) {
	_ = expectedTotal
	if event.MessageType != "XLogData" || len(payload) < 25 || payload[0] != 'w' {
		return
	}
	if conn.walDecoder == nil {
		conn.walDecoder = newWALStreamDecoder()
	}
	startLSN, _, ok := readUint64(payload, 1)
	if !ok {
		return
	}
	walBytes := payload[25:]
	var records []walRecordSummary
	if truncated {
		records = conn.walDecoder.DecodePreview(startLSN, walBytes)
	} else {
		records = conn.walDecoder.Feed(startLSN, walBytes)
	}
	decoded := formatWALRecordSummaries(records, p.previewLimit)
	if decoded == "" {
		return
	}
	if event.Summary == "" {
		event.Summary = decoded
		return
	}
	event.Summary = strings.TrimSpace(event.Summary + " " + decoded)
}

func parseTruncatedClientCopyData(chunk Chunk, session Session, code byte, payload []byte, expectedTotal int, previewLimit int) Event {
	if len(payload) == 0 {
		return newEvent(chunk, session, "CopyData", code, expectedTotal, true, truncatedSummary(expectedTotal, 5, "copy data bytes=0"), "")
	}

	payloadTotal := expectedTotal - 5
	switch payload[0] {
	case 'r':
		parts := make([]string, 0, 5)
		if len(payload) >= 1+8 {
			writeLSN, _, _ := readUint64(payload, 1)
			parts = append(parts, fmt.Sprintf("write=%s", formatLSN(writeLSN)))
		}
		if len(payload) >= 1+8+8 {
			flushLSN, _, _ := readUint64(payload, 9)
			parts = append(parts, fmt.Sprintf("flush=%s", formatLSN(flushLSN)))
		}
		if len(payload) >= 1+8+8+8 {
			applyLSN, _, _ := readUint64(payload, 17)
			parts = append(parts, fmt.Sprintf("apply=%s", formatLSN(applyLSN)))
		}
		if len(payload) >= 1+8+8+8+8+1 {
			parts = append(parts, fmt.Sprintf("reply_requested=%t", payload[33] == 1))
		}
		parts = append(parts, fmt.Sprintf("wal_bytes_total=%d", maxInt(payloadTotal-1, 0)))
		parts = append(parts, fmt.Sprintf("wal_bytes_captured=%d", maxInt(len(payload)-1, 0)))
		return newEvent(chunk, session, "StandbyStatusUpdate", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, strings.Join(parts, " ")), "")
	case 'h':
		parts := make([]string, 0, 4)
		if len(payload) >= 1+8+4 {
			xmin, _, _ := readUint32(payload, 9)
			parts = append(parts, fmt.Sprintf("xmin=%d", xmin))
		}
		if len(payload) >= 1+8+4+4+4 {
			catalogXmin, _, _ := readUint32(payload, 17)
			parts = append(parts, fmt.Sprintf("catalog_xmin=%d", catalogXmin))
		}
		parts = append(parts, fmt.Sprintf("wal_bytes_total=%d", maxInt(payloadTotal-1, 0)))
		parts = append(parts, fmt.Sprintf("wal_bytes_captured=%d", maxInt(len(payload)-1, 0)))
		return newEvent(chunk, session, "HotStandbyFeedback", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, strings.Join(parts, " ")), "")
	default:
		return newEvent(chunk, session, "CopyData", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit))), "")
	}
}

func parseTruncatedServerCopyData(chunk Chunk, session Session, code byte, payload []byte, expectedTotal int, previewLimit int) Event {
	if len(payload) == 0 {
		return newEvent(chunk, session, "CopyData", code, expectedTotal, true, truncatedSummary(expectedTotal, 5, "copy data bytes=0"), "")
	}

	payloadTotal := expectedTotal - 5
	switch payload[0] {
	case 'w':
		parts := make([]string, 0, 4)
		if len(payload) >= 1+8 {
			startLSN, _, _ := readUint64(payload, 1)
			parts = append(parts, fmt.Sprintf("wal_start=%s", formatLSN(startLSN)))
		}
		if len(payload) >= 1+8+8 {
			endLSN, _, _ := readUint64(payload, 9)
			parts = append(parts, fmt.Sprintf("wal_end=%s", formatLSN(endLSN)))
		}
		parts = append(parts, fmt.Sprintf("wal_bytes_total=%d", maxInt(payloadTotal-25, 0)))
		parts = append(parts, fmt.Sprintf("wal_bytes_captured=%d", maxInt(len(payload)-25, 0)))
		return newEvent(chunk, session, "XLogData", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, strings.Join(parts, " ")), "")
	case 'k':
		parts := make([]string, 0, 4)
		if len(payload) >= 1+8 {
			endLSN, _, _ := readUint64(payload, 1)
			parts = append(parts, fmt.Sprintf("wal_end=%s", formatLSN(endLSN)))
		}
		if len(payload) >= 1+8+8+1 {
			parts = append(parts, fmt.Sprintf("reply_requested=%t", payload[17] == 1))
		}
		parts = append(parts, fmt.Sprintf("wal_bytes_total=%d", maxInt(payloadTotal-1, 0)))
		parts = append(parts, fmt.Sprintf("wal_bytes_captured=%d", maxInt(len(payload)-1, 0)))
		return newEvent(chunk, session, "PrimaryKeepaliveMessage", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, strings.Join(parts, " ")), "")
	default:
		return newEvent(chunk, session, "CopyData", code, expectedTotal, true, truncatedSummary(expectedTotal, len(payload)+5, fmt.Sprintf("payload=%s", previewBytes(payload, previewLimit))), "")
	}
}

func classifyTruncatedEventGroup(conn *connectionState, event Event) ContentGroup {
	switch event.MessageType {
	case "Startup", "SSLRequest", "GSSENCRequest", "CancelRequest", "PasswordMessage", "Terminate", "Authentication", "ParameterStatus", "BackendKeyData":
		return GroupConnectionConfig
	case "XLogData", "PrimaryKeepaliveMessage", "StandbyStatusUpdate", "HotStandbyFeedback", "CopyBothResponse":
		return GroupWALTransmission
	case "Query", "Parse":
		return classifySQLGroup(event.SQL, conn.replicationRequested)
	default:
		return activeGroup(conn)
	}
}

func truncatedSummary(expectedTotal int, capturedTotal int, base string) string {
	missing := expectedTotal - capturedTotal
	if missing < 0 {
		missing = 0
	}
	base = strings.TrimSpace(base)
	if base == "" {
		return fmt.Sprintf("truncated captured=%d expected=%d missing=%d", capturedTotal, expectedTotal, missing)
	}
	return fmt.Sprintf("%s truncated captured=%d expected=%d missing=%d", base, capturedTotal, expectedTotal, missing)
}

func newEvent(chunk Chunk, session Session, messageType string, code byte, length int, truncated bool, summary string, sql string) Event {
	return Event{
		OccurredAt:  time.Now(),
		PID:         chunk.PID,
		TID:         chunk.TID,
		CgroupID:    chunk.CgroupID,
		ConnPtr:     chunk.ConnPtr,
		Comm:        chunk.Comm,
		Direction:   chunk.Direction,
		API:         chunk.API,
		MessageType: messageType,
		MessageCode: code,
		MessageLen:  length,
		Truncated:   truncated,
		Session:     session,
		Summary:     strings.TrimSpace(summary),
		SQL:         sql,
	}
}

func findRegularMessageStart(buffer []byte, direction Direction) int {
	for i := 0; i+5 <= len(buffer); i++ {
		code := buffer[i]
		if !isKnownMessageCode(direction, code) {
			continue
		}
		length := int(binary.BigEndian.Uint32(buffer[i+1 : i+5]))
		if length < 4 || length > maxMessageLength {
			continue
		}
		if i+1+length <= len(buffer) {
			return i
		}
	}
	return -1
}

func isKnownMessageCode(direction Direction, code byte) bool {
	switch direction {
	case DirectionClientToServer:
		return strings.ContainsRune("QPBDECSHXpfdcF", rune(code))
	case DirectionServerToClient:
		return strings.ContainsRune("RSKZTDCEN123InsAtGHWdv", rune(code))
	default:
		return false
	}
}

func parseErrorFields(payload []byte) map[string]string {
	fields := make(map[string]string)
	offset := 0
	for offset < len(payload) {
		fieldType := payload[offset]
		offset++
		if fieldType == 0 {
			break
		}
		value, next, ok := readCString(payload, offset)
		if !ok {
			break
		}
		offset = next
		fields[string(fieldType)] = value
	}
	return fields
}

func saslMechanisms(payload []byte) string {
	var mechs []string
	offset := 0
	for offset < len(payload) {
		mech, next, ok := readCString(payload, offset)
		if !ok || mech == "" {
			break
		}
		offset = next
		mechs = append(mechs, mech)
	}
	if len(mechs) == 0 {
		return "<unknown>"
	}
	return strings.Join(mechs, ",")
}

func authTypeName(code int32) string {
	switch code {
	case 0:
		return "Ok"
	case 2:
		return "KerberosV5"
	case 3:
		return "CleartextPassword"
	case 5:
		return "MD5Password"
	case 7:
		return "GSS"
	case 8:
		return "GSSContinue"
	case 9:
		return "SSPI"
	case 10:
		return "SASL"
	case 11:
		return "SASLContinue"
	case 12:
		return "SASLFinal"
	default:
		return fmt.Sprintf("Auth%d", code)
	}
}

func transactionStatus(code byte) string {
	switch code {
	case 'I':
		return "idle"
	case 'T':
		return "in_txn"
	case 'E':
		return "failed_txn"
	default:
		return fmt.Sprintf("state_%s", formatCode(code))
	}
}

func clientMessageName(code byte) string {
	switch code {
	case 'F':
		return "FunctionCall"
	default:
		return fmt.Sprintf("Client[%s]", formatCode(code))
	}
}

func serverMessageName(code byte) string {
	switch code {
	case 'G':
		return "CopyInResponse"
	case 'H':
		return "CopyOutResponse"
	case 'W':
		return "CopyBothResponse"
	case 'v':
		return "NegotiateProtocolVersion"
	default:
		return fmt.Sprintf("Server[%s]", formatCode(code))
	}
}

func readCString(buf []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(buf) {
		return "", 0, false
	}
	for i := offset; i < len(buf); i++ {
		if buf[i] == 0 {
			return string(buf[offset:i]), i + 1, true
		}
	}
	return "", 0, false
}

func readInt16(buf []byte, offset int) (int16, int, bool) {
	if offset < 0 || offset+2 > len(buf) {
		return 0, 0, false
	}
	return int16(binary.BigEndian.Uint16(buf[offset : offset+2])), offset + 2, true
}

func readInt32(buf []byte, offset int) (int32, int, bool) {
	if offset < 0 || offset+4 > len(buf) {
		return 0, 0, false
	}
	return int32(binary.BigEndian.Uint32(buf[offset : offset+4])), offset + 4, true
}

func readUint32(buf []byte, offset int) (uint32, int, bool) {
	if offset < 0 || offset+4 > len(buf) {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(buf[offset : offset+4]), offset + 4, true
}

func readUint64(buf []byte, offset int) (uint64, int, bool) {
	if offset < 0 || offset+8 > len(buf) {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(buf[offset : offset+8]), offset + 8, true
}

func previewString(value string, limit int) string {
	if value == "" {
		return `""`
	}
	return fmt.Sprintf("%q", previewBytes([]byte(value), limit))
}

func previewBytes(buf []byte, limit int) string {
	if len(buf) == 0 {
		return "<empty>"
	}
	if limit <= 0 || limit > len(buf) {
		limit = len(buf)
	}
	out := make([]byte, 0, limit)
	for _, b := range buf[:limit] {
		if b >= 32 && b <= 126 {
			out = append(out, b)
			continue
		}
		out = append(out, '.')
	}
	text := string(out)
	if len(buf) > limit {
		text += "..."
	}
	return text
}

func emptyLabel(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatCode(code byte) string {
	if code >= 32 && code <= 126 {
		return fmt.Sprintf("%q", rune(code))
	}
	return fmt.Sprintf("0x%02x", code)
}

func formatLSN(value uint64) string {
	return fmt.Sprintf("%X/%X", uint32(value>>32), uint32(value))
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
