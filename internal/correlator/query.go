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
	"fmt"
	"sort"
	"strings"

	"nahuel/internal/model"
)

func FilterSnapshot(snapshot Snapshot, query model.Query) Snapshot {
	out := snapshot
	out.Connections = FilterConnections(snapshot.Connections, query)
	allowed := make(map[string]struct{}, len(out.Connections))
	for _, conn := range out.Connections {
		allowed[conn.Connection.ID] = struct{}{}
	}
	out.Recent = FilterRecent(snapshot.Recent, query, allowed)
	return out
}

func FilterConnections(in []ConnectionView, query model.Query) []ConnectionView {
	out := make([]ConnectionView, 0, len(in))
	for _, view := range in {
		if query.MatchConnection(view.Connection) {
			out = append(out, view)
		}
	}
	SortConnections(out, strings.ToLower(query.Sort))
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit]
	}
	return out
}

func FilterRecent(in []ProtocolEvent, query model.Query, allowed map[string]struct{}) []ProtocolEvent {
	out := make([]ProtocolEvent, 0, len(in))
	for _, event := range in {
		if len(allowed) > 0 {
			if _, ok := allowed[event.ConnectionID]; !ok {
				continue
			}
		} else if !matchProtocolEvent(query, event) {
			continue
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit]
	}
	return out
}

func matchProtocolEvent(query model.Query, event ProtocolEvent) bool {
	if !matchEndpoint(query.Client, event.ClientAddr, event.ClientPort) {
		return false
	}
	if !matchEndpoint(query.Server, event.ServerAddr, event.ServerPort) {
		return false
	}
	if query.PID != 0 && event.PID != query.PID {
		return false
	}
	if query.Netns != 0 && event.Netns != query.Netns {
		return false
	}
	if query.CgroupID != 0 && event.CgroupID != query.CgroupID {
		return false
	}
	return true
}

func matchEndpoint(filter, address string, port uint16) bool {
	if filter == "" {
		return true
	}
	filter = strings.ToLower(filter)
	endpoint := strings.ToLower(fmt.Sprintf("%s:%d", address, port))
	return strings.Contains(strings.ToLower(address), filter) || strings.Contains(endpoint, filter)
}
