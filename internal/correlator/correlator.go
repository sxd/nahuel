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
	"sync"
	"time"

	"nahuel/internal/model"
	"nahuel/internal/procnet"
	"nahuel/internal/wire"
)

type GroupStats struct {
	TxBytes    uint64    `json:"tx_bytes"`
	RxBytes    uint64    `json:"rx_bytes"`
	Messages   uint64    `json:"messages"`
	LastType   string    `json:"last_type,omitempty"`
	LastDetail string    `json:"last_detail,omitempty"`
	LastSQL    string    `json:"last_sql,omitempty"`
	LastAt     time.Time `json:"last_at,omitempty"`
}

type ConnectionView struct {
	Connection model.Connection `json:"connection"`
	Session    wire.Session     `json:"session"`
	QueriesSQL GroupStats       `json:"queries_sql"`
	Config     GroupStats       `json:"connection_configuration"`
	WAL        GroupStats       `json:"wal_transmission"`
	LastGroup  string           `json:"last_group,omitempty"`
	LastType   string           `json:"last_type,omitempty"`
	LastDetail string           `json:"last_detail,omitempty"`
	LastSQL    string           `json:"last_sql,omitempty"`
	LastAt     time.Time        `json:"last_at,omitempty"`
}

type ProtocolEvent struct {
	OccurredAt   time.Time         `json:"occurred_at"`
	ConnectionID string            `json:"connection_id,omitempty"`
	ClientAddr   string            `json:"client_addr,omitempty"`
	ClientPort   uint16            `json:"client_port,omitempty"`
	ServerAddr   string            `json:"server_addr,omitempty"`
	ServerPort   uint16            `json:"server_port,omitempty"`
	Netns        uint32            `json:"netns,omitempty"`
	PID          uint32            `json:"pid"`
	CgroupID     uint64            `json:"cgroup_id"`
	CommandName  string            `json:"comm,omitempty"`
	Group        wire.ContentGroup `json:"group"`
	Direction    string            `json:"direction"`
	API          string            `json:"api"`
	MessageType  string            `json:"message_type"`
	MessageLen   int               `json:"message_len"`
	User         string            `json:"user,omitempty"`
	Database     string            `json:"database,omitempty"`
	Application  string            `json:"application,omitempty"`
	Detail       string            `json:"detail,omitempty"`
	SQL          string            `json:"sql,omitempty"`
}

type Snapshot struct {
	CapturedAt      time.Time           `json:"captured_at"`
	Port            uint16              `json:"port"`
	NetworkObserver model.ObserverStats `json:"network_observer"`
	WireAttachMode  string              `json:"nahuel_wire_attach_mode"`
	WireExecutables []string            `json:"nahuel_wire_executables,omitempty"`
	Connections     []ConnectionView    `json:"connections"`
	Recent          []ProtocolEvent     `json:"recent_protocol_events"`
}

type processKey struct {
	pid      uint32
	cgroupID uint64
}

type connectionMeta struct {
	ConnectionID string
	ClientAddr   string
	ClientPort   uint16
	ServerAddr   string
	ServerPort   uint16
	Netns        uint32
	PID          uint32
	CgroupID     uint64
	CommandName  string
}

type connectionAggregate struct {
	Session    wire.Session
	Queries    GroupStats
	Config     GroupStats
	WAL        GroupStats
	LastGroup  string
	LastType   string
	LastDetail string
	LastSQL    string
	LastAt     time.Time
}

type Correlator struct {
	mu        sync.Mutex
	byConnID  map[string]*connectionAggregate
	pending   map[processKey]*connectionAggregate
	recent    []ProtocolEvent
	procExact map[processKey]string
	procByPID map[uint32]string
	connMeta  map[string]connectionMeta
}

func New() *Correlator {
	return &Correlator{
		byConnID:  make(map[string]*connectionAggregate),
		pending:   make(map[processKey]*connectionAggregate),
		procExact: make(map[processKey]string),
		procByPID: make(map[uint32]string),
		connMeta:  make(map[string]connectionMeta),
	}
}

func (c *Correlator) Handle(event wire.Event) {
	key := processKey{pid: event.PID, cgroupID: event.CgroupID}

	c.mu.Lock()
	defer c.mu.Unlock()

	meta, connID := c.resolveMetaLocked(key)
	agg := c.lookupAggregateLocked(connID, key)
	c.applyEventLocked(agg, event)
	c.appendRecentLocked(event, connID, meta)
}

func (c *Correlator) BuildSnapshot(port uint16, network model.Snapshot, wireAttachMode string, executables []string, recentLimit int) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.refreshProcessMapsLocked(port, network.Connections)

	connections := make([]ConnectionView, 0, len(network.Connections))
	for _, conn := range network.Connections {
		agg := c.byConnID[conn.ID]
		view := ConnectionView{Connection: conn}
		if agg != nil {
			view.Session = agg.Session
			view.QueriesSQL = agg.Queries
			view.Config = agg.Config
			view.WAL = agg.WAL
			view.LastGroup = agg.LastGroup
			view.LastType = agg.LastType
			view.LastDetail = agg.LastDetail
			view.LastSQL = agg.LastSQL
			view.LastAt = agg.LastAt
		}
		connections = append(connections, view)
	}

	recent := append([]ProtocolEvent(nil), c.recent...)
	if recentLimit > 0 && len(recent) > recentLimit {
		recent = recent[:recentLimit]
	}

	return Snapshot{
		CapturedAt:      network.CapturedAt,
		Port:            port,
		NetworkObserver: network.Observer,
		WireAttachMode:  wireAttachMode,
		WireExecutables: append([]string(nil), executables...),
		Connections:     connections,
		Recent:          recent,
	}
}

func connectionLookupKey(clientAddr string, clientPort uint16, serverAddr string, serverPort uint16, netns uint32) string {
	return fmt.Sprintf("%s|%d|%s|%d|%d", clientAddr, clientPort, serverAddr, serverPort, netns)
}

func (c *Correlator) refreshProcessMapsLocked(port uint16, conns []model.Connection) {
	exact := make(map[processKey]string, len(conns))
	pidCandidates := make(map[uint32][]string)
	meta := make(map[string]connectionMeta, len(conns))
	byEndpoint := make(map[string]string, len(conns))
	candidatePIDs := make(map[uint32]struct{})

	for _, conn := range conns {
		entry := connectionMeta{
			ConnectionID: conn.ID,
			ClientAddr:   conn.ClientAddr,
			ClientPort:   conn.ClientPort,
			ServerAddr:   conn.ServerAddr,
			ServerPort:   conn.ServerPort,
			Netns:        conn.Netns,
			PID:          conn.LastPID,
			CgroupID:     conn.CgroupID,
			CommandName:  conn.Command,
		}
		meta[conn.ID] = entry
		byEndpoint[connectionLookupKey(conn.ClientAddr, conn.ClientPort, conn.ServerAddr, conn.ServerPort, conn.Netns)] = conn.ID
		if conn.LastPID == 0 {
			continue
		}
		candidatePIDs[conn.LastPID] = struct{}{}
		key := processKey{pid: conn.LastPID, cgroupID: conn.CgroupID}
		exact[key] = conn.ID
		pidCandidates[conn.LastPID] = append(pidCandidates[conn.LastPID], conn.ID)
	}

	for key := range c.pending {
		candidatePIDs[key.pid] = struct{}{}
	}
	for _, event := range c.recent {
		if event.ConnectionID == "" && event.PID != 0 {
			candidatePIDs[event.PID] = struct{}{}
		}
	}

	pidOnly := make(map[uint32]string, len(pidCandidates))
	for pid, ids := range pidCandidates {
		if len(ids) == 1 {
			pidOnly[pid] = ids[0]
		}
	}
	for pid := range candidatePIDs {
		if _, ok := pidOnly[pid]; ok {
			continue
		}
		matches, err := procnet.FindTCPConnections(pid, port)
		if err != nil {
			continue
		}
		var connID string
		for _, match := range matches {
			id, ok := byEndpoint[connectionLookupKey(match.ClientAddr, match.ClientPort, match.ServerAddr, match.ServerPort, match.Netns)]
			if !ok {
				id, ok = byEndpoint[connectionLookupKey(match.ClientAddr, match.ClientPort, match.ServerAddr, match.ServerPort, 0)]
			}
			if !ok {
				continue
			}
			if connID != "" && connID != id {
				connID = ""
				break
			}
			connID = id
		}
		if connID != "" {
			pidOnly[pid] = connID
		}
	}

	c.procExact = exact
	c.procByPID = pidOnly
	c.connMeta = meta
	c.flushPendingLocked()
}

func (c *Correlator) flushPendingLocked() {
	for key, pending := range c.pending {
		_, connID := c.resolveMetaLocked(key)
		if connID == "" {
			continue
		}
		target := c.byConnID[connID]
		if target == nil {
			target = &connectionAggregate{}
			c.byConnID[connID] = target
		}
		mergeAggregate(target, pending)
		delete(c.pending, key)
		for idx := range c.recent {
			if c.recent[idx].ConnectionID != "" {
				continue
			}
			if c.recent[idx].PID != key.pid || c.recent[idx].CgroupID != key.cgroupID {
				continue
			}
			if meta, ok := c.connMeta[connID]; ok {
				fillProtocolEventMeta(&c.recent[idx], connID, meta)
			}
		}
	}
}

func (c *Correlator) resolveMetaLocked(key processKey) (connectionMeta, string) {
	if connID, ok := c.procExact[key]; ok {
		return c.connMeta[connID], connID
	}
	if connID, ok := c.procByPID[key.pid]; ok {
		return c.connMeta[connID], connID
	}
	return connectionMeta{}, ""
}

func (c *Correlator) lookupAggregateLocked(connID string, key processKey) *connectionAggregate {
	if connID != "" {
		agg := c.byConnID[connID]
		if agg == nil {
			agg = &connectionAggregate{}
			c.byConnID[connID] = agg
		}
		return agg
	}
	agg := c.pending[key]
	if agg == nil {
		agg = &connectionAggregate{}
		c.pending[key] = agg
	}
	return agg
}

func (c *Correlator) applyEventLocked(agg *connectionAggregate, event wire.Event) {
	agg.Session = event.Session
	stats := selectGroupStats(agg, event.Group)
	if event.Direction == wire.DirectionServerToClient {
		stats.TxBytes += uint64(event.MessageLen)
	} else {
		stats.RxBytes += uint64(event.MessageLen)
	}
	stats.Messages++
	stats.LastType = event.MessageType
	stats.LastDetail = event.Summary
	stats.LastSQL = event.SQL
	stats.LastAt = event.OccurredAt
	agg.LastGroup = event.Group.String()
	agg.LastType = event.MessageType
	agg.LastDetail = event.Summary
	agg.LastSQL = event.SQL
	agg.LastAt = event.OccurredAt
}

func (c *Correlator) appendRecentLocked(event wire.Event, connID string, meta connectionMeta) {
	record := ProtocolEvent{
		OccurredAt:   event.OccurredAt,
		ConnectionID: connID,
		PID:          event.PID,
		CgroupID:     event.CgroupID,
		CommandName:  event.Comm,
		Group:        normalizedGroup(event.Group),
		Direction:    event.Direction.String(),
		API:          event.API.String(),
		MessageType:  event.MessageType,
		MessageLen:   event.MessageLen,
		User:         event.Session.User,
		Database:     event.Session.Database,
		Application:  event.Session.Application,
		Detail:       event.Summary,
		SQL:          event.SQL,
	}
	if connID != "" {
		fillProtocolEventMeta(&record, connID, meta)
	}
	c.recent = append([]ProtocolEvent{record}, c.recent...)
	if len(c.recent) > 100 {
		c.recent = c.recent[:100]
	}
}

func selectGroupStats(agg *connectionAggregate, group wire.ContentGroup) *GroupStats {
	switch normalizedGroup(group) {
	case wire.GroupConnectionConfig:
		return &agg.Config
	case wire.GroupWALTransmission:
		return &agg.WAL
	default:
		return &agg.Queries
	}
}

func normalizedGroup(group wire.ContentGroup) wire.ContentGroup {
	switch group {
	case wire.GroupConnectionConfig, wire.GroupWALTransmission:
		return group
	default:
		return wire.GroupQueriesSQL
	}
}

func fillProtocolEventMeta(record *ProtocolEvent, connID string, meta connectionMeta) {
	record.ConnectionID = connID
	record.ClientAddr = meta.ClientAddr
	record.ClientPort = meta.ClientPort
	record.ServerAddr = meta.ServerAddr
	record.ServerPort = meta.ServerPort
	record.Netns = meta.Netns
}

func mergeAggregate(dst, src *connectionAggregate) {
	mergeGroupStats(&dst.Queries, src.Queries)
	mergeGroupStats(&dst.Config, src.Config)
	mergeGroupStats(&dst.WAL, src.WAL)
	if src.Session.User != "" || src.Session.Database != "" || src.Session.Application != "" || src.Session.Replication {
		dst.Session = src.Session
	}
	if src.LastAt.After(dst.LastAt) {
		dst.LastGroup = src.LastGroup
		dst.LastType = src.LastType
		dst.LastDetail = src.LastDetail
		dst.LastSQL = src.LastSQL
		dst.LastAt = src.LastAt
	}
}

func mergeGroupStats(dst *GroupStats, src GroupStats) {
	dst.TxBytes += src.TxBytes
	dst.RxBytes += src.RxBytes
	dst.Messages += src.Messages
	if src.LastAt.After(dst.LastAt) {
		dst.LastType = src.LastType
		dst.LastDetail = src.LastDetail
		dst.LastSQL = src.LastSQL
		dst.LastAt = src.LastAt
	}
}

func SortConnections(views []ConnectionView, sortKey string) {
	sort.Slice(views, func(i, j int) bool {
		left := views[i].Connection
		right := views[j].Connection
		switch sortKey {
		case "tx":
			if left.BytesSent == right.BytesSent {
				return left.BytesRecv > right.BytesRecv
			}
			return left.BytesSent > right.BytesSent
		case "rx":
			if left.BytesRecv == right.BytesRecv {
				return left.BytesSent > right.BytesSent
			}
			return left.BytesRecv > right.BytesRecv
		case "age":
			return left.Age > right.Age
		case "retransmits":
			if left.Retransmits == right.Retransmits {
				return left.BytesSent+left.BytesRecv > right.BytesSent+right.BytesRecv
			}
			return left.Retransmits > right.Retransmits
		default:
			leftRate := left.SendRate + left.RecvRate
			rightRate := right.SendRate + right.RecvRate
			if leftRate == rightRate {
				return left.BytesSent+left.BytesRecv > right.BytesSent+right.BytesRecv
			}
			return leftRate > rightRate
		}
	})
}
