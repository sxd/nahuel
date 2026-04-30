/*
 * Copyright 2026 Jonathan Gonzalez V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PGNETMON_COMMON_H
#define __PGNETMON_COMMON_H

#define PG_COMM_LEN 16
#define PG_MAX_ENTRIES 16384
#define PG_INFLIGHT_ENTRIES 8192

enum conn_event_type {
	CONN_EVENT_ESTABLISHED = 1,
	CONN_EVENT_CLOSED = 2,
	CONN_EVENT_RETRANSMIT = 3,
};

enum close_reason {
	CLOSE_REASON_UNKNOWN = 0,
	CLOSE_REASON_FIN = 1,
	CLOSE_REASON_RESET = 2,
	CLOSE_REASON_TIMEOUT = 3,
	CLOSE_REASON_ABORT = 4,
};

struct conn_key {
	__u16 family;
	__u16 server_port;
	__u16 client_port;
	__u16 pad;
	__u32 netns;
	__u32 reserved;
	__u64 cgroup_id;
	__u8 server_addr[16];
	__u8 client_addr[16];
};

struct conn_stats {
	__u64 start_ns;
	__u64 last_seen_ns;
	__u64 bytes_sent;
	__u64 bytes_received;
	__u64 retransmits;
	__u64 resets;
	__u64 cgroup_id;
	__u32 last_pid;
	__u32 current_state;
	__s32 last_error;
	__u32 close_reason;
	char comm[PG_COMM_LEN];
};

struct conn_event {
	struct conn_key key;
	struct conn_stats stats;
	__u64 timestamp_ns;
	__u32 type;
	__u32 old_state;
	__u32 new_state;
	__u32 pad;
};

struct sendmsg_call {
	struct conn_key key;
	__u32 current_state;
	__u32 last_pid;
	char comm[PG_COMM_LEN];
};

#endif
