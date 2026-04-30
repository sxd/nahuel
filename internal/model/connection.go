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
	"bytes"
	"fmt"
	"net"
	"time"
)

type Connection struct {
	ID          string
	ClientAddr  string
	ClientPort  uint16
	ServerAddr  string
	ServerPort  uint16
	Netns       uint32
	CgroupID    uint64
	State       string
	BytesSent   uint64
	BytesRecv   uint64
	SendRate    float64
	RecvRate    float64
	Retransmits uint64
	Resets      uint64
	Age         time.Duration
	Idle        time.Duration
	LastPID     uint32
	Command     string
}

type ClosedConnection struct {
	ClientAddr  string
	ClientPort  uint16
	ServerAddr  string
	ServerPort  uint16
	Netns       uint32
	CgroupID    uint64
	State       string
	CloseReason string
	BytesSent   uint64
	BytesRecv   uint64
	Retransmits uint64
	Resets      uint64
	LastPID     uint32
	Command     string
	ClosedAt    time.Time
}

type ConnectionEvent struct {
	Type        string
	ClientAddr  string
	ClientPort  uint16
	ServerAddr  string
	ServerPort  uint16
	Netns       uint32
	CgroupID    uint64
	State       string
	CloseReason string
	BytesSent   uint64
	BytesRecv   uint64
	Retransmits uint64
	Resets      uint64
	LastPID     uint32
	Command     string
	OccurredAt  time.Time
}

type ObserverStats struct {
	AttachMode        string
	EstablishedEvents uint64
	ClosedEvents      uint64
	RetransmitEvents  uint64
	DroppedEvents     uint64
	LastLoopError     string
}

type Snapshot struct {
	CapturedAt  time.Time
	Connections []Connection
	Closed      []ClosedConnection
	Observer    ObserverStats
}

func AddressString(family uint16, raw [16]byte) string {
	switch family {
	case 2:
		return net.IP(raw[:4]).String()
	case 10:
		return net.IP(raw[:]).String()
	default:
		return "unknown"
	}
}

func CommString(raw [16]byte) string {
	return string(bytes.TrimRight(raw[:], "\x00"))
}

func ConnectionID(family uint16, clientAddr string, clientPort uint16, serverAddr string, serverPort uint16, netns uint32, cgroupID uint64) string {
	return fmt.Sprintf("%d|%s|%d|%s|%d|%d|%d", family, clientAddr, clientPort, serverAddr, serverPort, netns, cgroupID)
}

func TCPStateName(state uint32) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

func CloseReasonName(reason uint32) string {
	switch reason {
	case 1:
		return "FIN"
	case 2:
		return "RESET"
	case 3:
		return "TIMEOUT"
	case 4:
		return "ABORT"
	default:
		return "UNKNOWN"
	}
}
