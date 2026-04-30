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

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "wire.h"

#ifndef BPF_UPROBE
#define BPF_UPROBE(name, args...) BPF_KPROBE(name, ##args)
#endif

#ifndef BPF_URETPROBE
#define BPF_URETPROBE(name, args...) BPF_KRETPROBE(name, ##args)
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} wire_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, WIRE_INFLIGHT_ENTRIES);
	__type(key, __u64);
	__type(value, struct wire_inflight);
} wire_inflight SEC(".maps");

static __always_inline int save_inflight(__u64 conn_ptr,
					 __u64 buf_ptr,
					 __u32 requested_len,
					 __u8 direction,
					 __u8 api)
{
	struct wire_inflight inflight = {};
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	inflight.conn_ptr = conn_ptr;
	inflight.buf_ptr = buf_ptr;
	inflight.requested_len = requested_len;
	inflight.direction = direction;
	inflight.api = api;

	bpf_map_update_elem(&wire_inflight, &pid_tgid, &inflight, BPF_ANY);
	return 0;
}

static __always_inline void copy_user_data(__u8 *dst, const void *src, __u32 len)
{
	const char *user_ptr = src;
	__u32 offset = 0;

#pragma unroll
	for (int i = 0; i < WIRE_CAPTURE_BYTES / 64; i++) {
		if (offset + 64 > len)
			break;
		bpf_probe_read_user(dst + offset, 64, user_ptr + offset);
		offset += 64;
	}

#pragma unroll
	for (int i = 0; i < 64; i++) {
		if (offset + i >= len)
			break;
		bpf_probe_read_user(dst + offset + i, 1, user_ptr + offset + i);
	}
}

static __always_inline int emit_event(const struct wire_inflight *inflight, __u32 total_len)
{
	struct wire_event *event;
	__u32 copy_len;
	__u64 pid_tgid;

	if (!inflight || total_len == 0)
		return 0;

	copy_len = total_len;
	if (copy_len > WIRE_CAPTURE_BYTES)
		copy_len = WIRE_CAPTURE_BYTES;
	if (copy_len >= sizeof(event->data))
		copy_len = sizeof(event->data) - 1;

	event = bpf_ringbuf_reserve(&wire_events, sizeof(*event), 0);
	if (!event)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->conn_ptr = inflight->conn_ptr;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->pid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->total_len = total_len;
	event->captured_len = copy_len;
	event->direction = inflight->direction;
	event->api = inflight->api;
	event->truncated = total_len > copy_len;
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	if (copy_len > 0)
		copy_user_data(event->data, (const void *)inflight->buf_ptr, copy_len);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uprobe/secure_write")
int BPF_UPROBE(track_secure_write_enter, void *port, const void *buf, size_t size)
{
	return save_inflight((__u64)port, (__u64)buf, (__u32)size,
			     WIRE_DIR_SERVER_TO_CLIENT, WIRE_API_SECURE_WRITE);
}

SEC("uretprobe/secure_write")
int BPF_URETPROBE(track_secure_write_exit, long ret)
{
	struct wire_inflight *inflight;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	inflight = bpf_map_lookup_elem(&wire_inflight, &pid_tgid);
	if (!inflight)
		return 0;

	if (ret > 0)
		emit_event(inflight, (__u32)ret);

	bpf_map_delete_elem(&wire_inflight, &pid_tgid);
	return 0;
}

SEC("uprobe/secure_read")
int BPF_UPROBE(track_secure_read_enter, void *port, void *buf, size_t size)
{
	return save_inflight((__u64)port, (__u64)buf, (__u32)size,
			     WIRE_DIR_CLIENT_TO_SERVER, WIRE_API_SECURE_READ);
}

SEC("uretprobe/secure_read")
int BPF_URETPROBE(track_secure_read_exit, long ret)
{
	struct wire_inflight *inflight;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	inflight = bpf_map_lookup_elem(&wire_inflight, &pid_tgid);
	if (!inflight)
		return 0;

	if (ret > 0)
		emit_event(inflight, (__u32)ret);

	bpf_map_delete_elem(&wire_inflight, &pid_tgid);
	return 0;
}

SEC("uprobe/be_tls_write")
int BPF_UPROBE(track_be_tls_write_enter, void *port, const void *buf, size_t size, int *waitfor)
{
	return save_inflight((__u64)port, (__u64)buf, (__u32)size,
			     WIRE_DIR_SERVER_TO_CLIENT, WIRE_API_BE_TLS_WRITE);
}

SEC("uretprobe/be_tls_write")
int BPF_URETPROBE(track_be_tls_write_exit, long ret)
{
	struct wire_inflight *inflight;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	inflight = bpf_map_lookup_elem(&wire_inflight, &pid_tgid);
	if (!inflight)
		return 0;

	if (ret > 0)
		emit_event(inflight, (__u32)ret);

	bpf_map_delete_elem(&wire_inflight, &pid_tgid);
	return 0;
}

SEC("uprobe/be_tls_read")
int BPF_UPROBE(track_be_tls_read_enter, void *port, void *buf, size_t size, int *waitfor)
{
	return save_inflight((__u64)port, (__u64)buf, (__u32)size,
			     WIRE_DIR_CLIENT_TO_SERVER, WIRE_API_BE_TLS_READ);
}

SEC("uretprobe/be_tls_read")
int BPF_URETPROBE(track_be_tls_read_exit, long ret)
{
	struct wire_inflight *inflight;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	inflight = bpf_map_lookup_elem(&wire_inflight, &pid_tgid);
	if (!inflight)
		return 0;

	if (ret > 0)
		emit_event(inflight, (__u32)ret);

	bpf_map_delete_elem(&wire_inflight, &pid_tgid);
	return 0;
}
