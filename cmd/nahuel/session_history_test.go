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

package main

import (
	"testing"
	"time"

	"nahuel/internal/correlator"
)

func TestSessionEventHistoryKeepsNewestFirstAndDeduplicates(t *testing.T) {
	base := time.Unix(1700000000, 0)
	history := newSessionEventHistory(4)

	first := correlator.ProtocolEvent{OccurredAt: base.Add(3 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "client->server", API: "secure_read", MessageType: "Query", MessageLen: 12, Detail: "select 1"}
	second := correlator.ProtocolEvent{OccurredAt: base.Add(2 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "server->client", API: "secure_write", MessageType: "CommandComplete", MessageLen: 14, Detail: "SELECT 1"}

	merged := history.Merge([]correlator.ProtocolEvent{first, second})
	if len(merged) != 2 {
		t.Fatalf("expected 2 events, got %d", len(merged))
	}
	if merged[0].OccurredAt != first.OccurredAt || merged[1].OccurredAt != second.OccurredAt {
		t.Fatalf("unexpected order after first merge: %#v", merged)
	}

	merged = history.Merge([]correlator.ProtocolEvent{first})
	if len(merged) != 2 {
		t.Fatalf("expected duplicate event to be ignored, got %d entries", len(merged))
	}

	third := correlator.ProtocolEvent{OccurredAt: base.Add(4 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "server->client", API: "secure_write", MessageType: "ReadyForQuery", MessageLen: 6, Detail: "idle"}
	merged = history.Merge([]correlator.ProtocolEvent{third, first})
	if len(merged) != 3 {
		t.Fatalf("expected 3 unique events, got %d", len(merged))
	}
	if merged[0].OccurredAt != third.OccurredAt {
		t.Fatalf("expected newest event first, got %#v", merged)
	}
}

func TestSessionEventHistoryRetainsEventsOnEmptySnapshotAndCaps(t *testing.T) {
	base := time.Unix(1700000000, 0)
	history := newSessionEventHistory(2)

	first := correlator.ProtocolEvent{OccurredAt: base.Add(1 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "client->server", API: "secure_read", MessageType: "Query", MessageLen: 12}
	second := correlator.ProtocolEvent{OccurredAt: base.Add(2 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "server->client", API: "secure_write", MessageType: "CommandComplete", MessageLen: 14}
	third := correlator.ProtocolEvent{OccurredAt: base.Add(3 * time.Second), ConnectionID: "conn-1", PID: 10, Direction: "server->client", API: "secure_write", MessageType: "ReadyForQuery", MessageLen: 6}

	history.Merge([]correlator.ProtocolEvent{second, first})
	merged := history.Merge(nil)
	if len(merged) != 2 {
		t.Fatalf("expected empty merge to retain history, got %d", len(merged))
	}

	merged = history.Merge([]correlator.ProtocolEvent{third})
	if len(merged) != 2 {
		t.Fatalf("expected capped history size 2, got %d", len(merged))
	}
	if merged[0].OccurredAt != third.OccurredAt || merged[1].OccurredAt != second.OccurredAt {
		t.Fatalf("unexpected capped order: %#v", merged)
	}
}
