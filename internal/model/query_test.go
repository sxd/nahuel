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

package model

import (
	"testing"
	"time"
)

func TestQueryApplySnapshotFiltersAndSortsConnections(t *testing.T) {
	snapshot := Snapshot{
		Connections: []Connection{
			{
				ClientAddr:  "10.0.0.5",
				ClientPort:  50000,
				ServerAddr:  "10.0.0.10",
				ServerPort:  5432,
				CgroupID:    200,
				LastPID:     22,
				BytesSent:   200,
				BytesRecv:   100,
				Retransmits: 1,
				Age:         5 * time.Second,
			},
			{
				ClientAddr:  "10.0.0.2",
				ClientPort:  40000,
				ServerAddr:  "10.0.0.10",
				ServerPort:  5432,
				CgroupID:    100,
				LastPID:     11,
				BytesSent:   500,
				BytesRecv:   300,
				Retransmits: 3,
				Age:         10 * time.Second,
			},
		},
	}

	query := Query{
		Client:   "10.0.0.",
		CgroupID: 100,
		Sort:     "tx",
		Limit:    1,
	}

	filtered := query.ApplySnapshot(snapshot)
	if len(filtered.Connections) != 1 {
		t.Fatalf("expected 1 connection after filtering, got %d", len(filtered.Connections))
	}
	if filtered.Connections[0].LastPID != 11 {
		t.Fatalf("unexpected connection after filtering: pid=%d", filtered.Connections[0].LastPID)
	}
}

func TestQueryMatchesEvents(t *testing.T) {
	query := Query{
		Server: "db:5432",
		PID:    77,
		Netns:  42,
	}

	event := ConnectionEvent{
		ServerAddr: "db",
		ServerPort: 5432,
		LastPID:    77,
		Netns:      42,
	}
	if !query.MatchEvent(event) {
		t.Fatal("expected event to match query")
	}

	event.LastPID = 78
	if query.MatchEvent(event) {
		t.Fatal("expected event not to match query")
	}
}
