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
	"strings"
	"testing"
)

func TestParserStartupAndQuery(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)

	startup := makeStartupPacket(map[string]string{
		"user":             "appuser",
		"database":         "postgres",
		"application_name": "psql",
	})
	events := parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      startup,
	})
	if len(events) != 1 {
		t.Fatalf("expected 1 startup event, got %d", len(events))
	}
	if events[0].MessageType != "Startup" {
		t.Fatalf("expected Startup, got %s", events[0].MessageType)
	}
	if events[0].Session.User != "appuser" || events[0].Session.Database != "postgres" || events[0].Session.Application != "psql" {
		t.Fatalf("unexpected session: %#v", events[0].Session)
	}

	query := makeRegularMessage('Q', append([]byte("select 1"), 0))
	events = parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      query,
	})
	if len(events) != 1 {
		t.Fatalf("expected 1 query event, got %d", len(events))
	}
	if events[0].MessageType != "Query" {
		t.Fatalf("expected Query, got %s", events[0].MessageType)
	}
	if events[0].SQL != "select 1" {
		t.Fatalf("unexpected SQL: %q", events[0].SQL)
	}
	if events[0].Session.User != "appuser" {
		t.Fatalf("expected session propagation, got %#v", events[0].Session)
	}
}

func TestParserReassemblesAcrossChunks(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	msg := makeRegularMessage('Q', append([]byte("select 42"), 0))

	first := msg[:3]
	second := msg[3:]

	events := parser.Feed(Chunk{
		PID:       10,
		ConnPtr:   1,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      first,
	})
	if len(events) != 0 {
		t.Fatalf("expected no event from partial chunk, got %d", len(events))
	}

	events = parser.Feed(Chunk{
		PID:       10,
		ConnPtr:   1,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      second,
	})
	if len(events) != 1 {
		t.Fatalf("expected one event after reassembly, got %d", len(events))
	}
	if events[0].SQL != "select 42" {
		t.Fatalf("unexpected SQL after reassembly: %q", events[0].SQL)
	}
}

func TestParserServerErrorResponse(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	payload := append([]byte{'S'}, append([]byte("ERROR"), 0)...)
	payload = append(payload, 'C')
	payload = append(payload, append([]byte("42601"), 0)...)
	payload = append(payload, 'M')
	payload = append(payload, append([]byte("syntax error"), 0)...)
	payload = append(payload, 0)

	events := parser.Feed(Chunk{
		PID:       20,
		ConnPtr:   2,
		Direction: DirectionServerToClient,
		API:       APISecureWrite,
		Data:      makeRegularMessage('E', payload),
	})
	if len(events) != 1 {
		t.Fatalf("expected one error event, got %d", len(events))
	}
	if events[0].MessageType != "ErrorResponse" {
		t.Fatalf("expected ErrorResponse, got %s", events[0].MessageType)
	}
	if got := events[0].Summary; got == "" || got == "severity= code= message=" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestQueryMatch(t *testing.T) {
	query := Query{
		PID:       55,
		CgroupID:  9,
		Direction: "out",
		Types:     []string{"ReadyForQuery"},
	}
	event := Event{
		PID:         55,
		CgroupID:    9,
		Direction:   DirectionServerToClient,
		MessageType: "ReadyForQuery",
	}
	if !query.Match(event) {
		t.Fatalf("expected query to match event")
	}
}

func TestParserUsesConfigurableDetailLimit(t *testing.T) {
	parser := NewParser(16)
	sql := "select 1234567890abcdefXYZ"
	events := parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      makeStartupPacket(map[string]string{"user": "appuser"}),
	})
	if len(events) != 1 {
		t.Fatalf("expected startup event, got %d", len(events))
	}

	events = parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      makeRegularMessage('Q', append([]byte(sql), 0)),
	})
	if len(events) != 1 {
		t.Fatalf("expected query event, got %d", len(events))
	}
	if got := events[0].Summary; !strings.Contains(got, "...") {
		t.Fatalf("expected truncated summary, got %q", got)
	}
}

func TestParserUnlimitedDetailLimitDoesNotTruncate(t *testing.T) {
	parser := NewParser(0)
	sql := "select 1234567890abcdefXYZ"
	_ = parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      makeStartupPacket(map[string]string{"user": "appuser"}),
	})

	events := parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      makeRegularMessage('Q', append([]byte(sql), 0)),
	})
	if len(events) != 1 {
		t.Fatalf("expected query event, got %d", len(events))
	}
	if got := events[0].Summary; strings.Contains(got, "...") {
		t.Fatalf("expected untruncated summary, got %q", got)
	}
}

func TestQueryDoesNotUseSubstringMatch(t *testing.T) {
	query := Query{
		Types: []string{"Query"},
	}
	event := Event{
		MessageType: "ReadyForQuery",
	}
	if query.Match(event) {
		t.Fatalf("expected exact type matching, but substring match occurred")
	}
}

func TestQueryMatchesTypeList(t *testing.T) {
	query := Query{
		Types: []string{"Query", "ReadyForQuery"},
	}
	if !query.Match(Event{MessageType: "Query"}) {
		t.Fatalf("expected Query to match the type list")
	}
	if !query.Match(Event{MessageType: "ReadyForQuery"}) {
		t.Fatalf("expected ReadyForQuery to match the type list")
	}
	if query.Match(Event{MessageType: "EmptyQueryResponse"}) {
		t.Fatalf("expected EmptyQueryResponse not to match the type list")
	}
}

func makeRegularMessage(code byte, payload []byte) []byte {
	out := make([]byte, 1+4+len(payload))
	out[0] = code
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)+4))
	copy(out[5:], payload)
	return out
}

func makeStartupPacket(params map[string]string) []byte {
	payload := make([]byte, 0, 64)
	payload = append(payload, 0, 3, 0, 0)
	for _, key := range []string{"user", "database", "application_name", "replication", "options"} {
		value, ok := params[key]
		if !ok {
			continue
		}
		payload = append(payload, key...)
		payload = append(payload, 0)
		payload = append(payload, value...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)

	packet := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(packet)))
	copy(packet[4:], payload)
	return packet
}

func TestParserDecodesTruncatedServerXLogData(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	payload := makeXLogDataPayload(0x0000000200000010, 0x0000000200000210, 8192)
	message := makeRegularMessage('d', payload)
	captured := 128
	if captured >= len(message) {
		captured = len(message) - 1
	}

	events := parser.Feed(Chunk{
		PID:         42,
		ConnPtr:     7,
		Direction:   DirectionServerToClient,
		API:         APISecureWrite,
		TotalLen:    uint32(len(message)),
		CapturedLen: uint32(captured),
		Truncated:   true,
		Data:        append([]byte(nil), message[:captured]...),
	})
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].MessageType != "XLogData" {
		t.Fatalf("expected XLogData, got %s", events[0].MessageType)
	}
	if !events[0].Truncated {
		t.Fatal("expected truncated event")
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected WAL group, got %q", events[0].Group)
	}
	if events[0].MessageLen != len(message) {
		t.Fatalf("expected message len %d, got %d", len(message), events[0].MessageLen)
	}
	if !strings.Contains(events[0].Summary, "wal_start=2/10") || !strings.Contains(events[0].Summary, "wal_end=2/210") {
		t.Fatalf("expected WAL LSNs in summary, got %q", events[0].Summary)
	}
	if !strings.Contains(events[0].Summary, "wal_bytes_total=8192") || !strings.Contains(events[0].Summary, "truncated captured=128 expected=") {
		t.Fatalf("expected WAL size/truncation details in summary, got %q", events[0].Summary)
	}
}

func TestParserDecodesTruncatedClientStandbyStatusUpdate(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	startup := makeStartupPacket(map[string]string{
		"user":        "replicator",
		"replication": "true",
	})
	if events := parser.Feed(Chunk{PID: 84, ConnPtr: 9, Direction: DirectionClientToServer, API: APISecureRead, Data: startup}); len(events) != 1 {
		t.Fatalf("expected startup event, got %d", len(events))
	}
	payload := makeStandbyStatusPayload(0x0000000300000040, 0x0000000300000040, 0x0000000300000040, true)
	message := makeRegularMessage('d', payload)
	captured := len(message) - 2

	events := parser.Feed(Chunk{
		PID:         84,
		ConnPtr:     9,
		Direction:   DirectionClientToServer,
		API:         APISecureRead,
		TotalLen:    uint32(len(message)),
		CapturedLen: uint32(captured),
		Truncated:   true,
		Data:        append([]byte(nil), message[:captured]...),
	})
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].MessageType != "StandbyStatusUpdate" {
		t.Fatalf("expected StandbyStatusUpdate, got %s", events[0].MessageType)
	}
	if !events[0].Truncated {
		t.Fatal("expected truncated event")
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected WAL group, got %q", events[0].Group)
	}
	if events[0].MessageLen != len(message) {
		t.Fatalf("expected message len %d, got %d", len(message), events[0].MessageLen)
	}
	if !strings.Contains(events[0].Summary, "write=3/40") || !strings.Contains(events[0].Summary, "flush=3/40") || !strings.Contains(events[0].Summary, "apply=3/40") {
		t.Fatalf("expected standby status LSNs in summary, got %q", events[0].Summary)
	}
	if !strings.Contains(events[0].Summary, "wal_bytes_total=33") || !strings.Contains(events[0].Summary, "truncated captured=") {
		t.Fatalf("expected WAL size/truncation details in summary, got %q", events[0].Summary)
	}
}
