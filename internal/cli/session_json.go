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
	"io"
	"time"

	"nahuel/internal/branding"
	"nahuel/internal/correlator"
)

type sessionSnapshotRecord struct {
	Component       string                       `json:"component"`
	Command         string                       `json:"command"`
	Kind            string                       `json:"kind"`
	Port            uint16                       `json:"port"`
	CapturedAt      string                       `json:"captured_at"`
	NetworkObserver any                          `json:"network_observer"`
	WireAttachMode  string                       `json:"nahuel_wire_attach_mode"`
	WireExecutables []string                     `json:"nahuel_wire_executables,omitempty"`
	Connections     []sessionConnectionRecord    `json:"connections"`
	Recent          []sessionProtocolEventRecord `json:"recent_protocol_events"`
}

type sessionObserverRecord struct {
	AttachMode        string `json:"attach_mode"`
	EstablishedEvents uint64 `json:"established_events"`
	ClosedEvents      uint64 `json:"closed_events"`
	RetransmitEvents  uint64 `json:"retransmit_events"`
	DroppedEvents     uint64 `json:"dropped_events"`
	LastLoopError     string `json:"last_loop_error,omitempty"`
}

type sessionConnectionRecord struct {
	ID              string                `json:"id"`
	ClientAddr      string                `json:"client_addr"`
	ClientPort      uint16                `json:"client_port"`
	ClientEndpoint  string                `json:"client_endpoint"`
	ServerAddr      string                `json:"server_addr"`
	ServerPort      uint16                `json:"server_port"`
	ServerEndpoint  string                `json:"server_endpoint"`
	Netns           uint32                `json:"netns"`
	CgroupID        uint64                `json:"cgroup_id"`
	State           string                `json:"state"`
	BytesSent       uint64                `json:"bytes_sent"`
	BytesRecv       uint64                `json:"bytes_recv"`
	SendRate        float64               `json:"send_rate"`
	RecvRate        float64               `json:"recv_rate"`
	Retransmits     uint64                `json:"retransmits"`
	Resets          uint64                `json:"resets"`
	AgeMs           int64                 `json:"age_ms"`
	IdleMs          int64                 `json:"idle_ms"`
	PID             uint32                `json:"pid"`
	CommandName     string                `json:"comm"`
	SessionUser     string                `json:"user,omitempty"`
	SessionDatabase string                `json:"database,omitempty"`
	SessionApp      string                `json:"application,omitempty"`
	QueriesSQL      correlator.GroupStats `json:"queries_sql"`
	Config          correlator.GroupStats `json:"connection_configuration"`
	WAL             correlator.GroupStats `json:"wal_transmission"`
	LastGroup       string                `json:"last_group,omitempty"`
	LastType        string                `json:"last_type,omitempty"`
	LastDetail      string                `json:"last_detail,omitempty"`
	LastSQL         string                `json:"last_sql,omitempty"`
	LastAt          string                `json:"last_at,omitempty"`
}

type sessionProtocolEventRecord struct {
	OccurredAt     string `json:"occurred_at"`
	ConnectionID   string `json:"connection_id,omitempty"`
	ClientAddr     string `json:"client_addr,omitempty"`
	ClientPort     uint16 `json:"client_port,omitempty"`
	ClientEndpoint string `json:"client_endpoint,omitempty"`
	ServerAddr     string `json:"server_addr,omitempty"`
	ServerPort     uint16 `json:"server_port,omitempty"`
	ServerEndpoint string `json:"server_endpoint,omitempty"`
	Netns          uint32 `json:"netns,omitempty"`
	PID            uint32 `json:"pid"`
	CgroupID       uint64 `json:"cgroup_id"`
	CommandName    string `json:"comm,omitempty"`
	Group          string `json:"group"`
	Direction      string `json:"direction"`
	API            string `json:"api"`
	MessageType    string `json:"message_type"`
	MessageLen     int    `json:"message_len"`
	User           string `json:"user,omitempty"`
	Database       string `json:"database,omitempty"`
	Application    string `json:"application,omitempty"`
	Detail         string `json:"detail,omitempty"`
	SQL            string `json:"sql,omitempty"`
}

func RenderSessionSnapshotJSON(w io.Writer, snapshot correlator.Snapshot) error {
	record := sessionSnapshotRecord{
		Component:  branding.ProjectName,
		Command:    branding.MonitorCommandName + "/session",
		Kind:       "snapshot",
		Port:       snapshot.Port,
		CapturedAt: snapshot.CapturedAt.Format(time.RFC3339Nano),
		NetworkObserver: sessionObserverRecord{
			AttachMode:        snapshot.NetworkObserver.AttachMode,
			EstablishedEvents: snapshot.NetworkObserver.EstablishedEvents,
			ClosedEvents:      snapshot.NetworkObserver.ClosedEvents,
			RetransmitEvents:  snapshot.NetworkObserver.RetransmitEvents,
			DroppedEvents:     snapshot.NetworkObserver.DroppedEvents,
			LastLoopError:     snapshot.NetworkObserver.LastLoopError,
		},
		WireAttachMode:  snapshot.WireAttachMode,
		WireExecutables: append([]string(nil), snapshot.WireExecutables...),
		Connections:     make([]sessionConnectionRecord, 0, len(snapshot.Connections)),
		Recent:          make([]sessionProtocolEventRecord, 0, len(snapshot.Recent)),
	}
	for _, view := range snapshot.Connections {
		lastAt := ""
		if !view.LastAt.IsZero() {
			lastAt = view.LastAt.Format(time.RFC3339Nano)
		}
		record.Connections = append(record.Connections, sessionConnectionRecord{
			ID:              view.Connection.ID,
			ClientAddr:      view.Connection.ClientAddr,
			ClientPort:      view.Connection.ClientPort,
			ClientEndpoint:  endpoint(view.Connection.ClientAddr, view.Connection.ClientPort),
			ServerAddr:      view.Connection.ServerAddr,
			ServerPort:      view.Connection.ServerPort,
			ServerEndpoint:  endpoint(view.Connection.ServerAddr, view.Connection.ServerPort),
			Netns:           view.Connection.Netns,
			CgroupID:        view.Connection.CgroupID,
			State:           view.Connection.State,
			BytesSent:       view.Connection.BytesSent,
			BytesRecv:       view.Connection.BytesRecv,
			SendRate:        view.Connection.SendRate,
			RecvRate:        view.Connection.RecvRate,
			Retransmits:     view.Connection.Retransmits,
			Resets:          view.Connection.Resets,
			AgeMs:           view.Connection.Age.Milliseconds(),
			IdleMs:          view.Connection.Idle.Milliseconds(),
			PID:             view.Connection.LastPID,
			CommandName:     view.Connection.Command,
			SessionUser:     view.Session.User,
			SessionDatabase: view.Session.Database,
			SessionApp:      view.Session.Application,
			QueriesSQL:      view.QueriesSQL,
			Config:          view.Config,
			WAL:             view.WAL,
			LastGroup:       view.LastGroup,
			LastType:        view.LastType,
			LastDetail:      view.LastDetail,
			LastSQL:         view.LastSQL,
			LastAt:          lastAt,
		})
	}
	for _, event := range snapshot.Recent {
		record.Recent = append(record.Recent, sessionProtocolEventRecord{
			OccurredAt:     event.OccurredAt.Format(time.RFC3339Nano),
			ConnectionID:   event.ConnectionID,
			ClientAddr:     event.ClientAddr,
			ClientPort:     event.ClientPort,
			ClientEndpoint: maybeEndpoint(event.ClientAddr, event.ClientPort),
			ServerAddr:     event.ServerAddr,
			ServerPort:     event.ServerPort,
			ServerEndpoint: maybeEndpoint(event.ServerAddr, event.ServerPort),
			Netns:          event.Netns,
			PID:            event.PID,
			CgroupID:       event.CgroupID,
			CommandName:    event.CommandName,
			Group:          event.Group.String(),
			Direction:      event.Direction,
			API:            event.API,
			MessageType:    event.MessageType,
			MessageLen:     event.MessageLen,
			User:           event.User,
			Database:       event.Database,
			Application:    event.Application,
			Detail:         event.Detail,
			SQL:            event.SQL,
		})
	}
	return writeJSON(w, record)
}

func maybeEndpoint(address string, port uint16) string {
	if address == "" {
		return ""
	}
	return endpoint(address, port)
}
