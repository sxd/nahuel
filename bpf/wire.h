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

#ifndef __NAHUEL_WIRE_H
#define __NAHUEL_WIRE_H

#define WIRE_CAPTURE_BYTES 4096
#define WIRE_INFLIGHT_ENTRIES 16384

enum wire_direction {
	WIRE_DIR_CLIENT_TO_SERVER = 1,
	WIRE_DIR_SERVER_TO_CLIENT = 2,
};

enum wire_api {
	WIRE_API_SECURE_READ = 1,
	WIRE_API_SECURE_WRITE = 2,
	WIRE_API_BE_TLS_READ = 3,
	WIRE_API_BE_TLS_WRITE = 4,
};

struct wire_event {
	__u64 timestamp_ns;
	__u64 conn_ptr;
	__u64 cgroup_id;
	__u32 pid;
	__u32 tid;
	__u32 total_len;
	__u32 captured_len;
	__u8 direction;
	__u8 api;
	__u8 truncated;
	__u8 pad;
	char comm[16];
	__u8 data[WIRE_CAPTURE_BYTES + 1];
};

struct wire_inflight {
	__u64 conn_ptr;
	__u64 buf_ptr;
	__u32 requested_len;
	__u8 direction;
	__u8 api;
	__u16 pad;
};

#endif
