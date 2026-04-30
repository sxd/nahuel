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
	"fmt"
	"sort"
	"strings"
)

type Query struct {
	Client   string
	Server   string
	PID      uint32
	Netns    uint32
	CgroupID uint64
	Limit    int
	Sort     string
}

func (q Query) ApplySnapshot(snapshot Snapshot) Snapshot {
	out := snapshot
	out.Connections = q.FilterConnections(snapshot.Connections)
	out.Closed = q.FilterClosed(snapshot.Closed)
	return out
}

func (q Query) FilterConnections(in []Connection) []Connection {
	out := make([]Connection, 0, len(in))
	for _, conn := range in {
		if q.MatchConnection(conn) {
			out = append(out, conn)
		}
	}

	sortConnections(out, q.Sort)
	return applyLimit(out, q.Limit)
}

func (q Query) FilterClosed(in []ClosedConnection) []ClosedConnection {
	out := make([]ClosedConnection, 0, len(in))
	for _, conn := range in {
		if q.MatchClosed(conn) {
			out = append(out, conn)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ClosedAt.After(out[j].ClosedAt)
	})
	return applyLimit(out, q.Limit)
}

func (q Query) FilterEvents(in []ConnectionEvent) []ConnectionEvent {
	out := make([]ConnectionEvent, 0, len(in))
	for _, event := range in {
		if q.MatchEvent(event) {
			out = append(out, event)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	return applyLimit(out, q.Limit)
}

func (q Query) MatchConnection(conn Connection) bool {
	if !matchEndpoint(q.Client, conn.ClientAddr, conn.ClientPort) {
		return false
	}
	if !matchEndpoint(q.Server, conn.ServerAddr, conn.ServerPort) {
		return false
	}
	if q.PID != 0 && conn.LastPID != q.PID {
		return false
	}
	if q.Netns != 0 && conn.Netns != q.Netns {
		return false
	}
	if q.CgroupID != 0 && conn.CgroupID != q.CgroupID {
		return false
	}
	return true
}

func (q Query) MatchClosed(conn ClosedConnection) bool {
	if !matchEndpoint(q.Client, conn.ClientAddr, conn.ClientPort) {
		return false
	}
	if !matchEndpoint(q.Server, conn.ServerAddr, conn.ServerPort) {
		return false
	}
	if q.PID != 0 && conn.LastPID != q.PID {
		return false
	}
	if q.Netns != 0 && conn.Netns != q.Netns {
		return false
	}
	if q.CgroupID != 0 && conn.CgroupID != q.CgroupID {
		return false
	}
	return true
}

func (q Query) MatchEvent(event ConnectionEvent) bool {
	if !matchEndpoint(q.Client, event.ClientAddr, event.ClientPort) {
		return false
	}
	if !matchEndpoint(q.Server, event.ServerAddr, event.ServerPort) {
		return false
	}
	if q.PID != 0 && event.LastPID != q.PID {
		return false
	}
	if q.Netns != 0 && event.Netns != q.Netns {
		return false
	}
	if q.CgroupID != 0 && event.CgroupID != q.CgroupID {
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

func sortConnections(conns []Connection, sortKey string) {
	switch strings.ToLower(sortKey) {
	case "", "rate":
		sort.Slice(conns, func(i, j int) bool {
			left := conns[i].SendRate + conns[i].RecvRate
			right := conns[j].SendRate + conns[j].RecvRate
			if left == right {
				return conns[i].BytesSent+conns[i].BytesRecv > conns[j].BytesSent+conns[j].BytesRecv
			}
			return left > right
		})
	case "tx":
		sort.Slice(conns, func(i, j int) bool {
			if conns[i].BytesSent == conns[j].BytesSent {
				return conns[i].BytesRecv > conns[j].BytesRecv
			}
			return conns[i].BytesSent > conns[j].BytesSent
		})
	case "rx":
		sort.Slice(conns, func(i, j int) bool {
			if conns[i].BytesRecv == conns[j].BytesRecv {
				return conns[i].BytesSent > conns[j].BytesSent
			}
			return conns[i].BytesRecv > conns[j].BytesRecv
		})
	case "age":
		sort.Slice(conns, func(i, j int) bool {
			return conns[i].Age > conns[j].Age
		})
	case "retransmits":
		sort.Slice(conns, func(i, j int) bool {
			if conns[i].Retransmits == conns[j].Retransmits {
				return conns[i].BytesSent+conns[i].BytesRecv > conns[j].BytesSent+conns[j].BytesRecv
			}
			return conns[i].Retransmits > conns[j].Retransmits
		})
	default:
		sortConnections(conns, "rate")
	}
}

func applyLimit[T any](in []T, limit int) []T {
	if limit <= 0 || len(in) <= limit {
		return in
	}
	return in[:limit]
}
