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
	"encoding/json"
	"fmt"
	"io"
	"time"

	"nahuel/internal/branding"
	"nahuel/internal/model"
	"nahuel/internal/wire"
)

type snapshotRecord struct {
	Component         string                 `json:"component"`
	Command           string                 `json:"command"`
	Kind              string                 `json:"kind"`
	Port              uint16                 `json:"port"`
	CapturedAt        string                 `json:"captured_at"`
	AttachMode        string                 `json:"attach_mode"`
	EstablishedEvents uint64                 `json:"established_events"`
	ClosedEvents      uint64                 `json:"closed_events"`
	RetransmitEvents  uint64                 `json:"retransmit_events"`
	DroppedEvents     uint64                 `json:"dropped_events"`
	LastLoopError     string                 `json:"last_loop_error,omitempty"`
	ActiveConnections int                    `json:"active_connections"`
	RecentCloses      int                    `json:"recent_closes"`
	TotalBytesSent    uint64                 `json:"total_bytes_sent"`
	TotalBytesRecv    uint64                 `json:"total_bytes_recv"`
	Connections       []connectionRecord     `json:"connections"`
	Closed            []closedConnectionJSON `json:"recent_closed"`
}

type connectionEventRecord struct {
	Component      string `json:"component"`
	Command        string `json:"command"`
	Kind           string `json:"kind"`
	Port           uint16 `json:"port"`
	AttachMode     string `json:"attach_mode"`
	OccurredAt     string `json:"occurred_at"`
	EventType      string `json:"event_type"`
	ClientAddr     string `json:"client_addr"`
	ClientPort     uint16 `json:"client_port"`
	ClientEndpoint string `json:"client_endpoint"`
	ServerAddr     string `json:"server_addr"`
	ServerPort     uint16 `json:"server_port"`
	ServerEndpoint string `json:"server_endpoint"`
	Netns          uint32 `json:"netns"`
	CgroupID       uint64 `json:"cgroup_id"`
	State          string `json:"state"`
	CloseReason    string `json:"close_reason,omitempty"`
	BytesSent      uint64 `json:"bytes_sent"`
	BytesRecv      uint64 `json:"bytes_recv"`
	Retransmits    uint64 `json:"retransmits"`
	Resets         uint64 `json:"resets"`
	PID            uint32 `json:"pid"`
	CommandName    string `json:"comm"`
}

type wireStatusRecord struct {
	Component       string   `json:"component"`
	Command         string   `json:"command"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	AttachMode      string   `json:"attach_mode"`
	ExecutableCount int      `json:"executable_count"`
	Executables     []string `json:"executables,omitempty"`
	Chunks          uint64   `json:"chunks"`
	Parsed          uint64   `json:"parsed"`
	Rendered        uint64   `json:"rendered"`
	IdleMs          int64    `json:"idle_ms"`
}

type wireEventRecord struct {
	Component   string `json:"component"`
	Command     string `json:"command"`
	Kind        string `json:"kind"`
	AttachMode  string `json:"attach_mode"`
	OccurredAt  string `json:"occurred_at"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	CgroupID    uint64 `json:"cgroup_id"`
	ConnPtr     uint64 `json:"conn_ptr"`
	CommandName string `json:"comm"`
	Direction   string `json:"direction"`
	API         string `json:"api"`
	Group       string `json:"group"`
	MessageType string `json:"message_type"`
	MessageCode byte   `json:"message_code"`
	MessageLen  int    `json:"message_len"`
	Truncated   bool   `json:"truncated"`
	User        string `json:"user,omitempty"`
	Database    string `json:"database,omitempty"`
	Application string `json:"application,omitempty"`
	Detail      string `json:"detail,omitempty"`
	SQL         string `json:"sql,omitempty"`
}

type connectionRecord struct {
	ID             string  `json:"id"`
	ClientAddr     string  `json:"client_addr"`
	ClientPort     uint16  `json:"client_port"`
	ClientEndpoint string  `json:"client_endpoint"`
	ServerAddr     string  `json:"server_addr"`
	ServerPort     uint16  `json:"server_port"`
	ServerEndpoint string  `json:"server_endpoint"`
	Netns          uint32  `json:"netns"`
	CgroupID       uint64  `json:"cgroup_id"`
	State          string  `json:"state"`
	BytesSent      uint64  `json:"bytes_sent"`
	BytesRecv      uint64  `json:"bytes_recv"`
	SendRate       float64 `json:"send_rate"`
	RecvRate       float64 `json:"recv_rate"`
	Retransmits    uint64  `json:"retransmits"`
	Resets         uint64  `json:"resets"`
	AgeMs          int64   `json:"age_ms"`
	Age            string  `json:"age"`
	IdleMs         int64   `json:"idle_ms"`
	Idle           string  `json:"idle"`
	PID            uint32  `json:"pid"`
	CommandName    string  `json:"comm"`
}

type closedConnectionJSON struct {
	ClientAddr     string `json:"client_addr"`
	ClientPort     uint16 `json:"client_port"`
	ClientEndpoint string `json:"client_endpoint"`
	ServerAddr     string `json:"server_addr"`
	ServerPort     uint16 `json:"server_port"`
	ServerEndpoint string `json:"server_endpoint"`
	Netns          uint32 `json:"netns"`
	CgroupID       uint64 `json:"cgroup_id"`
	State          string `json:"state"`
	CloseReason    string `json:"close_reason"`
	BytesSent      uint64 `json:"bytes_sent"`
	BytesRecv      uint64 `json:"bytes_recv"`
	Retransmits    uint64 `json:"retransmits"`
	Resets         uint64 `json:"resets"`
	PID            uint32 `json:"pid"`
	CommandName    string `json:"comm"`
	ClosedAt       string `json:"closed_at"`
}

func RenderSnapshotJSON(w io.Writer, command string, port uint16, snapshot model.Snapshot) error {
	record := snapshotRecord{
		Component:         branding.ProjectName,
		Command:           branding.MonitorCommandName + "/" + command,
		Kind:              "snapshot",
		Port:              port,
		CapturedAt:        snapshot.CapturedAt.Format(time.RFC3339Nano),
		AttachMode:        snapshot.Observer.AttachMode,
		EstablishedEvents: snapshot.Observer.EstablishedEvents,
		ClosedEvents:      snapshot.Observer.ClosedEvents,
		RetransmitEvents:  snapshot.Observer.RetransmitEvents,
		DroppedEvents:     snapshot.Observer.DroppedEvents,
		LastLoopError:     snapshot.Observer.LastLoopError,
		ActiveConnections: len(snapshot.Connections),
		RecentCloses:      len(snapshot.Closed),
		Connections:       make([]connectionRecord, 0, len(snapshot.Connections)),
		Closed:            make([]closedConnectionJSON, 0, len(snapshot.Closed)),
	}

	for _, conn := range snapshot.Connections {
		record.TotalBytesSent += conn.BytesSent
		record.TotalBytesRecv += conn.BytesRecv
		record.Connections = append(record.Connections, connectionRecord{
			ID:             conn.ID,
			ClientAddr:     conn.ClientAddr,
			ClientPort:     conn.ClientPort,
			ClientEndpoint: endpoint(conn.ClientAddr, conn.ClientPort),
			ServerAddr:     conn.ServerAddr,
			ServerPort:     conn.ServerPort,
			ServerEndpoint: endpoint(conn.ServerAddr, conn.ServerPort),
			Netns:          conn.Netns,
			CgroupID:       conn.CgroupID,
			State:          conn.State,
			BytesSent:      conn.BytesSent,
			BytesRecv:      conn.BytesRecv,
			SendRate:       conn.SendRate,
			RecvRate:       conn.RecvRate,
			Retransmits:    conn.Retransmits,
			Resets:         conn.Resets,
			AgeMs:          conn.Age.Milliseconds(),
			Age:            conn.Age.String(),
			IdleMs:         conn.Idle.Milliseconds(),
			Idle:           conn.Idle.String(),
			PID:            conn.LastPID,
			CommandName:    conn.Command,
		})
	}

	for _, conn := range snapshot.Closed {
		record.Closed = append(record.Closed, closedConnectionJSON{
			ClientAddr:     conn.ClientAddr,
			ClientPort:     conn.ClientPort,
			ClientEndpoint: endpoint(conn.ClientAddr, conn.ClientPort),
			ServerAddr:     conn.ServerAddr,
			ServerPort:     conn.ServerPort,
			ServerEndpoint: endpoint(conn.ServerAddr, conn.ServerPort),
			Netns:          conn.Netns,
			CgroupID:       conn.CgroupID,
			State:          conn.State,
			CloseReason:    conn.CloseReason,
			BytesSent:      conn.BytesSent,
			BytesRecv:      conn.BytesRecv,
			Retransmits:    conn.Retransmits,
			Resets:         conn.Resets,
			PID:            conn.LastPID,
			CommandName:    conn.Command,
			ClosedAt:       conn.ClosedAt.Format(time.RFC3339Nano),
		})
	}

	return writeJSON(w, record)
}

func RenderConnectionEventJSON(w io.Writer, port uint16, attachMode string, event model.ConnectionEvent) error {
	return writeJSON(w, connectionEventRecord{
		Component:      branding.ProjectName,
		Command:        branding.MonitorCommandName + "/events",
		Kind:           "event",
		Port:           port,
		AttachMode:     attachMode,
		OccurredAt:     event.OccurredAt.Format(time.RFC3339Nano),
		EventType:      event.Type,
		ClientAddr:     event.ClientAddr,
		ClientPort:     event.ClientPort,
		ClientEndpoint: endpoint(event.ClientAddr, event.ClientPort),
		ServerAddr:     event.ServerAddr,
		ServerPort:     event.ServerPort,
		ServerEndpoint: endpoint(event.ServerAddr, event.ServerPort),
		Netns:          event.Netns,
		CgroupID:       event.CgroupID,
		State:          event.State,
		CloseReason:    event.CloseReason,
		BytesSent:      event.BytesSent,
		BytesRecv:      event.BytesRecv,
		Retransmits:    event.Retransmits,
		Resets:         event.Resets,
		PID:            event.LastPID,
		CommandName:    event.Command,
	})
}

func RenderWireStatusJSON(w io.Writer, attachMode string, executables []string, chunks uint64, parsed uint64, rendered uint64, idle time.Duration) error {
	state := "listening"
	if chunks == 0 {
		state = "waiting"
	}
	return writeJSON(w, wireStatusRecord{
		Component:       branding.ProjectName,
		Command:         branding.WireCommandName,
		Kind:            "status",
		State:           state,
		AttachMode:      attachMode,
		ExecutableCount: len(executables),
		Executables:     append([]string(nil), executables...),
		Chunks:          chunks,
		Parsed:          parsed,
		Rendered:        rendered,
		IdleMs:          idle.Milliseconds(),
	})
}

func RenderWireEventJSON(w io.Writer, attachMode string, event wire.Event) error {
	return writeJSON(w, wireEventRecord{
		Component:   branding.ProjectName,
		Command:     branding.WireCommandName,
		Kind:        "event",
		AttachMode:  attachMode,
		OccurredAt:  event.OccurredAt.Format(time.RFC3339Nano),
		PID:         event.PID,
		TID:         event.TID,
		CgroupID:    event.CgroupID,
		ConnPtr:     event.ConnPtr,
		CommandName: event.Comm,
		Direction:   event.Direction.String(),
		API:         event.API.String(),
		Group:       event.Group.String(),
		MessageType: event.MessageType,
		MessageCode: event.MessageCode,
		MessageLen:  event.MessageLen,
		Truncated:   event.Truncated,
		User:        event.Session.User,
		Database:    event.Session.Database,
		Application: event.Session.Application,
		Detail:      event.Summary,
		SQL:         event.SQL,
	})
}

func writeJSON(w io.Writer, value any) error {
	return json.NewEncoder(w).Encode(value)
}

func endpoint(address string, port uint16) string {
	return fmt.Sprintf("%s:%d", address, port)
}
