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

package correlator

import (
	"testing"
	"time"

	"nahuel/internal/model"
	"nahuel/internal/wire"
)

func TestCorrelatorBuildsPerConnectionGroupTotals(t *testing.T) {
	corr := New()
	now := time.Unix(1700000000, 0).UTC()
	network := model.Snapshot{
		CapturedAt: now,
		Connections: []model.Connection{{
			ID:         "conn-1",
			ClientAddr: "10.0.0.5",
			ClientPort: 40000,
			ServerAddr: "10.0.0.10",
			ServerPort: 5432,
			Netns:      7,
			CgroupID:   9,
			BytesSent:  200,
			BytesRecv:  100,
			LastPID:    1234,
			Command:    "postgres",
		}},
	}

	_ = corr.BuildSnapshot(5432, network, "uprobe:secure", []string{"/proc/1234/exe"}, 10)
	corr.Handle(wire.Event{
		OccurredAt:  now.Add(time.Second),
		PID:         1234,
		CgroupID:    9,
		Comm:        "postgres",
		Direction:   wire.DirectionClientToServer,
		API:         wire.APISecureRead,
		Group:       wire.GroupQueriesSQL,
		MessageType: "Query",
		MessageLen:  64,
		Session:     wire.Session{User: "app", Database: "postgres", Application: "psql"},
		Summary:     "query=select 1",
		SQL:         "select 1",
	})
	corr.Handle(wire.Event{
		OccurredAt:  now.Add(2 * time.Second),
		PID:         1234,
		CgroupID:    9,
		Comm:        "postgres",
		Direction:   wire.DirectionServerToClient,
		API:         wire.APISecureWrite,
		Group:       wire.GroupConnectionConfig,
		MessageType: "ParameterStatus",
		MessageLen:  32,
		Session:     wire.Session{User: "app", Database: "postgres", Application: "psql"},
		Summary:     "client_encoding=UTF8",
	})

	snapshot := corr.BuildSnapshot(5432, network, "uprobe:secure", []string{"/proc/1234/exe"}, 10)
	if len(snapshot.Connections) != 1 {
		t.Fatalf("expected one connection, got %d", len(snapshot.Connections))
	}
	view := snapshot.Connections[0]
	if view.QueriesSQL.RxBytes != 64 {
		t.Fatalf("expected query rx bytes 64, got %d", view.QueriesSQL.RxBytes)
	}
	if view.Config.TxBytes != 32 {
		t.Fatalf("expected config tx bytes 32, got %d", view.Config.TxBytes)
	}
	if view.Session.User != "app" {
		t.Fatalf("expected session user to propagate, got %q", view.Session.User)
	}
	if len(snapshot.Recent) != 2 {
		t.Fatalf("expected 2 recent events, got %d", len(snapshot.Recent))
	}
	if snapshot.Recent[0].ConnectionID != "conn-1" || snapshot.Recent[1].ConnectionID != "conn-1" {
		t.Fatalf("expected recent events to be correlated to conn-1: %#v", snapshot.Recent)
	}
}
