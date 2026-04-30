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
	"testing"
)

func TestParserAssignsConnectionConfigurationGroup(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	events := parser.Feed(Chunk{
		PID:       1234,
		ConnPtr:   99,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data: makeStartupPacket(map[string]string{
			"user":             "appuser",
			"database":         "postgres",
			"application_name": "psql",
		}),
	})
	if len(events) != 1 {
		t.Fatalf("expected one startup event, got %d", len(events))
	}
	if events[0].Group != GroupConnectionConfig {
		t.Fatalf("expected startup group %q, got %q", GroupConnectionConfig, events[0].Group)
	}
}

func TestParserAssignsConfigGroupToReplicationControlAndWALToStream(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)
	startup := makeStartupPacket(map[string]string{
		"user":             "replicator",
		"database":         "postgres",
		"application_name": "walreceiver",
		"replication":      "true",
	})
	if events := parser.Feed(Chunk{PID: 11, ConnPtr: 1, Direction: DirectionClientToServer, API: APISecureRead, Data: startup}); len(events) != 1 {
		t.Fatalf("expected startup event, got %d", len(events))
	}

	query := makeRegularMessage('Q', append([]byte("START_REPLICATION SLOT test PHYSICAL 0/0"), 0))
	events := parser.Feed(Chunk{PID: 11, ConnPtr: 1, Direction: DirectionClientToServer, API: APISecureRead, Data: query})
	if len(events) != 1 {
		t.Fatalf("expected one query event, got %d", len(events))
	}
	if events[0].Group != GroupConnectionConfig {
		t.Fatalf("expected replication control group %q, got %q", GroupConnectionConfig, events[0].Group)
	}

	copyBoth := makeRegularMessage('W', []byte{0, 0, 0, 0})
	events = parser.Feed(Chunk{PID: 11, ConnPtr: 1, Direction: DirectionServerToClient, API: APISecureWrite, Data: copyBoth})
	if len(events) != 1 {
		t.Fatalf("expected one copy-both event, got %d", len(events))
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected copy-both group %q, got %q", GroupWALTransmission, events[0].Group)
	}

	events = parser.Feed(Chunk{PID: 11, ConnPtr: 1, Direction: DirectionServerToClient, API: APISecureWrite, Data: makeRegularMessage('d', makeXLogDataPayload(0x0000000100000000, 0x0000000100000020, 32))})
	if len(events) != 1 {
		t.Fatalf("expected one xlog event, got %d", len(events))
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected xlog group %q, got %q", GroupWALTransmission, events[0].Group)
	}
	if events[0].MessageType != "XLogData" {
		t.Fatalf("expected XLogData, got %s", events[0].MessageType)
	}

	events = parser.Feed(Chunk{PID: 11, ConnPtr: 1, Direction: DirectionClientToServer, API: APISecureRead, Data: makeRegularMessage('d', makeStandbyStatusPayload(0x0000000100000040, 0x0000000100000040, 0x0000000100000040, true))})
	if len(events) != 1 {
		t.Fatalf("expected one standby status event, got %d", len(events))
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected standby status group %q, got %q", GroupWALTransmission, events[0].Group)
	}
	if events[0].MessageType != "StandbyStatusUpdate" {
		t.Fatalf("expected StandbyStatusUpdate, got %s", events[0].MessageType)
	}
}

func TestParserDetectsMidStreamReplicationPayloads(t *testing.T) {
	parser := NewParser(DefaultDetailLimit)

	events := parser.Feed(Chunk{
		PID:       77,
		ConnPtr:   9,
		Direction: DirectionServerToClient,
		API:       APISecureWrite,
		Data:      makeRegularMessage('d', makePrimaryKeepalivePayload(0x0000000200000010, true)),
	})
	if len(events) != 1 {
		t.Fatalf("expected one keepalive event, got %d", len(events))
	}
	if events[0].MessageType != "PrimaryKeepaliveMessage" {
		t.Fatalf("expected PrimaryKeepaliveMessage, got %s", events[0].MessageType)
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected keepalive group %q, got %q", GroupWALTransmission, events[0].Group)
	}

	events = parser.Feed(Chunk{
		PID:       77,
		ConnPtr:   9,
		Direction: DirectionClientToServer,
		API:       APISecureRead,
		Data:      makeRegularMessage('d', makeHotStandbyFeedbackPayload(42, 84)),
	})
	if len(events) != 1 {
		t.Fatalf("expected one hot standby feedback event, got %d", len(events))
	}
	if events[0].MessageType != "HotStandbyFeedback" {
		t.Fatalf("expected HotStandbyFeedback, got %s", events[0].MessageType)
	}
	if events[0].Group != GroupWALTransmission {
		t.Fatalf("expected hot standby feedback group %q, got %q", GroupWALTransmission, events[0].Group)
	}
}

func makeXLogDataPayload(startLSN uint64, endLSN uint64, walBytes int) []byte {
	if walBytes < 0 {
		walBytes = 0
	}
	payload := make([]byte, 1+8+8+8+walBytes)
	payload[0] = 'w'
	binary.BigEndian.PutUint64(payload[1:9], startLSN)
	binary.BigEndian.PutUint64(payload[9:17], endLSN)
	binary.BigEndian.PutUint64(payload[17:25], 0)
	for i := 25; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return payload
}

func makePrimaryKeepalivePayload(endLSN uint64, replyRequested bool) []byte {
	payload := make([]byte, 1+8+8+1)
	payload[0] = 'k'
	binary.BigEndian.PutUint64(payload[1:9], endLSN)
	binary.BigEndian.PutUint64(payload[9:17], 0)
	if replyRequested {
		payload[17] = 1
	}
	return payload
}

func makeStandbyStatusPayload(writeLSN uint64, flushLSN uint64, applyLSN uint64, replyRequested bool) []byte {
	payload := make([]byte, 1+8+8+8+8+1)
	payload[0] = 'r'
	binary.BigEndian.PutUint64(payload[1:9], writeLSN)
	binary.BigEndian.PutUint64(payload[9:17], flushLSN)
	binary.BigEndian.PutUint64(payload[17:25], applyLSN)
	binary.BigEndian.PutUint64(payload[25:33], 0)
	if replyRequested {
		payload[33] = 1
	}
	return payload
}

func makeHotStandbyFeedbackPayload(xmin uint32, catalogXmin uint32) []byte {
	payload := make([]byte, 1+8+4+4+4+4)
	payload[0] = 'h'
	binary.BigEndian.PutUint64(payload[1:9], 0)
	binary.BigEndian.PutUint32(payload[9:13], xmin)
	binary.BigEndian.PutUint32(payload[13:17], 0)
	binary.BigEndian.PutUint32(payload[17:21], catalogXmin)
	binary.BigEndian.PutUint32(payload[21:25], 0)
	return payload
}
