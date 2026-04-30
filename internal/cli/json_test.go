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

package cli

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"nahuel/internal/model"
	"nahuel/internal/wire"
)

func TestRenderSnapshotJSON(t *testing.T) {
	snapshot := model.Snapshot{
		CapturedAt: time.Unix(1700000000, 0).UTC(),
		Connections: []model.Connection{{
			ID:          "conn-1",
			ClientAddr:  "10.0.0.1",
			ClientPort:  40000,
			ServerAddr:  "10.0.0.2",
			ServerPort:  5432,
			BytesSent:   128,
			BytesRecv:   256,
			SendRate:    1.5,
			RecvRate:    2.5,
			Retransmits: 1,
			Resets:      0,
			Age:         5 * time.Second,
			Idle:        time.Second,
			LastPID:     42,
			Command:     "postgres",
		}},
		Observer: model.ObserverStats{
			AttachMode:        "tracing",
			EstablishedEvents: 7,
			ClosedEvents:      3,
		},
	}

	var buf bytes.Buffer
	if err := RenderSnapshotJSON(&buf, "watch", 5432, snapshot); err != nil {
		t.Fatalf("render snapshot json: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	if decoded["component"] != "nahuel" {
		t.Fatalf("unexpected component: %#v", decoded["component"])
	}
	if decoded["command"] != "mon/watch" {
		t.Fatalf("unexpected command: %#v", decoded["command"])
	}
	if decoded["kind"] != "snapshot" {
		t.Fatalf("unexpected kind: %#v", decoded["kind"])
	}
	if decoded["active_connections"] != float64(1) {
		t.Fatalf("unexpected active connection count: %#v", decoded["active_connections"])
	}
	if decoded["total_bytes_sent"] != float64(128) {
		t.Fatalf("unexpected total bytes sent: %#v", decoded["total_bytes_sent"])
	}
}

func TestRenderWireEventJSON(t *testing.T) {
	event := wire.Event{
		OccurredAt:  time.Unix(1700000000, 0).UTC(),
		PID:         123,
		TID:         456,
		CgroupID:    789,
		ConnPtr:     999,
		Comm:        "postgres",
		Direction:   wire.DirectionClientToServer,
		API:         wire.APISecureRead,
		MessageType: "Query",
		MessageCode: 'Q',
		MessageLen:  42,
		Truncated:   false,
		Session: wire.Session{
			User:        "postgres",
			Database:    "postgres",
			Application: "psql",
		},
		Summary: "select 1",
		SQL:     "select 1",
	}

	var buf bytes.Buffer
	if err := RenderWireEventJSON(&buf, "uprobe:secure", event); err != nil {
		t.Fatalf("render wire json: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	if decoded["component"] != "nahuel" {
		t.Fatalf("unexpected component: %#v", decoded["component"])
	}
	if decoded["command"] != "wire" {
		t.Fatalf("unexpected command: %#v", decoded["command"])
	}
	if decoded["message_type"] != "Query" {
		t.Fatalf("unexpected message type: %#v", decoded["message_type"])
	}
	if decoded["sql"] != "select 1" {
		t.Fatalf("unexpected sql: %#v", decoded["sql"])
	}
}
