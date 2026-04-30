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

package wire

import "strings"

type ContentGroup string

const (
	GroupQueriesSQL       ContentGroup = "queries_sql"
	GroupConnectionConfig ContentGroup = "connection_configuration"
	GroupWALTransmission  ContentGroup = "wal_transmission"
)

func (g ContentGroup) String() string {
	switch g {
	case GroupQueriesSQL:
		return "queries_sql"
	case GroupConnectionConfig:
		return "connection_configuration"
	case GroupWALTransmission:
		return "wal_transmission"
	default:
		return "queries_sql"
	}
}

func (g ContentGroup) Label() string {
	switch g {
	case GroupQueriesSQL:
		return "SQL"
	case GroupConnectionConfig:
		return "CONFIG"
	case GroupWALTransmission:
		return "WAL"
	default:
		return "SQL"
	}
}

func (p *Parser) applyStartupState(conn *connectionState, event *Event) {
	event.Group = GroupConnectionConfig
	conn.replicationRequested = event.Session.Replication
	conn.currentGroup = GroupConnectionConfig
	conn.copyGroup = ""
}

func (p *Parser) applyClientEventState(conn *connectionState, event *Event) {
	switch event.MessageType {
	case "Startup", "SSLRequest", "GSSENCRequest", "CancelRequest", "PasswordMessage", "Terminate":
		event.Group = GroupConnectionConfig
		if event.MessageType == "Terminate" {
			conn.currentGroup = GroupConnectionConfig
			conn.copyGroup = ""
		}
	case "Query", "Parse":
		group := classifySQLGroup(event.SQL, conn.replicationRequested)
		event.Group = group
		conn.currentGroup = group
		switch {
		case startsWalStreamingSQL(event.SQL):
			conn.copyGroup = GroupWALTransmission
		case isCopySQL(event.SQL):
			conn.copyGroup = GroupQueriesSQL
		default:
			conn.copyGroup = ""
		}
	case "StandbyStatusUpdate", "HotStandbyFeedback":
		event.Group = GroupWALTransmission
		conn.currentGroup = GroupWALTransmission
		conn.copyGroup = GroupWALTransmission
	case "CopyData", "CopyDone", "CopyFail":
		event.Group = activeGroup(conn)
		if event.MessageType == "CopyDone" || event.MessageType == "CopyFail" {
			conn.copyGroup = ""
		}
	default:
		event.Group = activeGroup(conn)
	}
}

func (p *Parser) applyServerEventState(conn *connectionState, event *Event) {
	switch event.MessageType {
	case "Authentication", "ParameterStatus", "BackendKeyData":
		event.Group = GroupConnectionConfig
	case "CopyInResponse", "CopyOutResponse":
		event.Group = activeQueryGroup(conn)
		conn.copyGroup = event.Group
	case "CopyBothResponse", "XLogData", "PrimaryKeepaliveMessage":
		event.Group = GroupWALTransmission
		conn.currentGroup = GroupWALTransmission
		conn.copyGroup = GroupWALTransmission
	case "CopyData", "CopyDone", "CopyFail":
		event.Group = activeGroup(conn)
		if event.MessageType == "CopyDone" || event.MessageType == "CopyFail" {
			conn.copyGroup = ""
		}
	case "ReadyForQuery":
		event.Group = activeQueryGroup(conn)
		conn.currentGroup = GroupQueriesSQL
		conn.copyGroup = ""
	default:
		event.Group = activeQueryGroup(conn)
	}
}

func activeGroup(conn *connectionState) ContentGroup {
	if conn.copyGroup != "" {
		return conn.copyGroup
	}
	return activeQueryGroup(conn)
}

func activeQueryGroup(conn *connectionState) ContentGroup {
	if conn.currentGroup != "" {
		return conn.currentGroup
	}
	return GroupQueriesSQL
}

func classifySQLGroup(sql string, replicationRequested bool) ContentGroup {
	normalized := normalizeSQL(sql)
	if normalized == "" {
		return GroupQueriesSQL
	}
	if looksLikeReplicationControlSQL(normalized) {
		return GroupConnectionConfig
	}
	if replicationRequested && (strings.HasPrefix(normalized, "start_replication") || strings.HasPrefix(normalized, "base_backup")) {
		return GroupConnectionConfig
	}
	return GroupQueriesSQL
}

func startsWalStreamingSQL(sql string) bool {
	normalized := normalizeSQL(sql)
	return strings.HasPrefix(normalized, "start_replication") || strings.HasPrefix(normalized, "base_backup")
}

func isCopySQL(sql string) bool {
	normalized := normalizeSQL(sql)
	return strings.HasPrefix(normalized, "copy ") || normalized == "copy"
}

func looksLikeReplicationControlSQL(normalized string) bool {
	for _, prefix := range []string{
		"start_replication",
		"identify_system",
		"create_replication_slot",
		"drop_replication_slot",
		"read_replication_slot",
		"timeline_history",
		"base_backup",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func normalizeSQL(sql string) string {
	sql = strings.TrimSpace(sql)
	sql = strings.TrimLeft(sql, "(")
	return strings.ToLower(strings.Join(strings.Fields(sql), " "))
}

func isReplicationStartup(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "1", "true", "yes", "database", "on":
		return true
	default:
		return false
	}
}
