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

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

#define PG_AF_INET 2
#define PG_AF_INET6 10

#define PG_TCP_ESTABLISHED 1
#define PG_TCP_FIN_WAIT1 4
#define PG_TCP_FIN_WAIT2 5
#define PG_TCP_TIME_WAIT 6
#define PG_TCP_CLOSE 7
#define PG_TCP_CLOSE_WAIT 8
#define PG_TCP_LAST_ACK 9
#define PG_TCP_CLOSING 11

#define PG_ECONNRESET 104
#define PG_ECONNABORTED 103
#define PG_ETIMEDOUT 110

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u16 target_port = 5432;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PG_MAX_ENTRIES);
	__type(key, struct conn_key);
	__type(value, struct conn_stats);
} active_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} conn_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PG_INFLIGHT_ENTRIES);
	__type(key, __u64);
	__type(value, struct sendmsg_call);
} inflight_send SEC(".maps");

static __always_inline __u64 read_sock_cgroup_id(struct sock *sk)
{
	struct cgroup *cgroup;

	cgroup = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
	if (!cgroup)
		return 0;

	return BPF_CORE_READ(cgroup, self.serial_nr);
}

static __always_inline int fill_conn_key(struct sock *sk, struct conn_key *key)
{
	__u16 family;
	__u16 local_port;
	__u16 remote_port;
	__u32 local_addr4;
	__u32 remote_addr4;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != PG_AF_INET && family != PG_AF_INET6)
		return -1;

	local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (local_port != target_port && remote_port != target_port)
		return -1;

	__builtin_memset(key, 0, sizeof(*key));
	key->family = family;
	key->server_port = target_port;
	key->client_port = local_port == target_port ? remote_port : local_port;
	key->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	key->cgroup_id = read_sock_cgroup_id(sk);

	if (family == PG_AF_INET) {
		local_addr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		remote_addr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		if (local_port == target_port) {
			__builtin_memcpy(key->server_addr, &local_addr4, sizeof(local_addr4));
			__builtin_memcpy(key->client_addr, &remote_addr4, sizeof(remote_addr4));
		} else {
			__builtin_memcpy(key->server_addr, &remote_addr4, sizeof(remote_addr4));
			__builtin_memcpy(key->client_addr, &local_addr4, sizeof(local_addr4));
		}

		return 0;
	}

	if (local_port == target_port) {
		BPF_CORE_READ_INTO(key->server_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(key->client_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		BPF_CORE_READ_INTO(key->server_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(key->client_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}

	return 0;
}

static __always_inline void update_process_metadata(struct conn_stats *stats)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	if (!pid)
		return;

	stats->last_pid = pid;
	bpf_get_current_comm(stats->comm, sizeof(stats->comm));
}

static __always_inline struct conn_stats *lookup_or_create_stats(struct sock *sk,
								 struct conn_key *key,
								 __u64 now,
								 int create)
{
	struct conn_stats zero = {};
	struct conn_stats *stats;

	if (fill_conn_key(sk, key) < 0)
		return NULL;

	stats = bpf_map_lookup_elem(&active_conns, key);
	if (stats || !create)
		goto out;

	zero.start_ns = now;
	zero.last_seen_ns = now;
	zero.current_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	zero.last_error = BPF_CORE_READ(sk, sk_err);
	zero.cgroup_id = key->cgroup_id;
	update_process_metadata(&zero);

	bpf_map_update_elem(&active_conns, key, &zero, BPF_ANY);
	stats = bpf_map_lookup_elem(&active_conns, key);

out:
	if (!stats)
		return NULL;

	if (!stats->start_ns)
		stats->start_ns = now;
	if (!stats->cgroup_id)
		stats->cgroup_id = key->cgroup_id;
	stats->last_seen_ns = now;
	return stats;
}

static __always_inline void emit_event(__u32 type,
				       __u32 old_state,
				       __u32 new_state,
				       const struct conn_key *key,
				       const struct conn_stats *stats)
{
	struct conn_event *event;

	event = bpf_ringbuf_reserve(&conn_events, sizeof(*event), 0);
	if (!event)
		return;

	__builtin_memset(event, 0, sizeof(*event));
	__builtin_memcpy(&event->key, key, sizeof(*key));
	__builtin_memcpy(&event->stats, stats, sizeof(*stats));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->type = type;
	event->old_state = old_state;
	event->new_state = new_state;

	bpf_ringbuf_submit(event, 0);
}

static __always_inline __u32 classify_close_reason(struct sock *sk, __u32 old_state)
{
	__s32 last_error = BPF_CORE_READ(sk, sk_err);

	if (last_error == -PG_ECONNRESET || last_error == PG_ECONNRESET)
		return CLOSE_REASON_RESET;
	if (last_error == -PG_ETIMEDOUT || last_error == PG_ETIMEDOUT)
		return CLOSE_REASON_TIMEOUT;
	if (last_error == -PG_ECONNABORTED || last_error == PG_ECONNABORTED)
		return CLOSE_REASON_ABORT;

	switch (old_state) {
	case PG_TCP_FIN_WAIT1:
	case PG_TCP_FIN_WAIT2:
	case PG_TCP_LAST_ACK:
	case PG_TCP_CLOSING:
	case PG_TCP_CLOSE_WAIT:
	case PG_TCP_TIME_WAIT:
		return CLOSE_REASON_FIN;
	default:
		return CLOSE_REASON_UNKNOWN;
	}
}

static __always_inline int handle_state_change(struct sock *sk, __u32 new_state)
{
	struct conn_key key = {};
	struct conn_stats *stats;
	__u32 old_state;
	__u64 now;

	old_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	now = bpf_ktime_get_ns();

	stats = lookup_or_create_stats(sk, &key, now, new_state != PG_TCP_CLOSE);
	if (!stats)
		return 0;

	update_process_metadata(stats);
	stats->current_state = new_state;
	stats->last_error = BPF_CORE_READ(sk, sk_err);

	if (new_state == PG_TCP_ESTABLISHED && old_state != PG_TCP_ESTABLISHED)
		emit_event(CONN_EVENT_ESTABLISHED, old_state, new_state, &key, stats);

	if (new_state == PG_TCP_CLOSE) {
		stats->close_reason = classify_close_reason(sk, old_state);
		if (stats->close_reason == CLOSE_REASON_RESET)
			__sync_fetch_and_add(&stats->resets, 1);
		emit_event(CONN_EVENT_CLOSED, old_state, new_state, &key, stats);
		bpf_map_delete_elem(&active_conns, &key);
	}

	return 0;
}

static __always_inline int account_bytes(struct sock *sk, __u64 bytes, int is_send)
{
	struct conn_key key = {};
	struct conn_stats *stats;
	__u64 now;

	if ((__s64)bytes <= 0)
		return 0;

	now = bpf_ktime_get_ns();
	stats = lookup_or_create_stats(sk, &key, now, 1);
	if (!stats)
		return 0;

	update_process_metadata(stats);
	stats->current_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	stats->last_error = BPF_CORE_READ(sk, sk_err);

	if (is_send)
		__sync_fetch_and_add(&stats->bytes_sent, bytes);
	else
		__sync_fetch_and_add(&stats->bytes_received, bytes);

	return 0;
}

static __always_inline int account_retransmit(struct sock *sk)
{
	struct conn_key key = {};
	struct conn_stats *stats;
	__u64 now;

	now = bpf_ktime_get_ns();
	stats = lookup_or_create_stats(sk, &key, now, 1);
	if (!stats)
		return 0;

	__sync_fetch_and_add(&stats->retransmits, 1);
	stats->last_seen_ns = now;
	stats->current_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	stats->last_error = BPF_CORE_READ(sk, sk_err);
	emit_event(CONN_EVENT_RETRANSMIT, stats->current_state, stats->current_state, &key, stats);
	return 0;
}

static __always_inline int account_send_from_call(const struct sendmsg_call *call, __u64 bytes)
{
	struct conn_stats zero = {};
	struct conn_stats *stats;
	__u64 now;

	if ((__s64)bytes <= 0)
		return 0;

	now = bpf_ktime_get_ns();
	stats = bpf_map_lookup_elem(&active_conns, &call->key);
	if (!stats) {
		zero.start_ns = now;
		zero.last_seen_ns = now;
		zero.current_state = call->current_state;
		zero.cgroup_id = call->key.cgroup_id;
		zero.last_pid = call->last_pid;
		__builtin_memcpy(zero.comm, call->comm, sizeof(zero.comm));
		bpf_map_update_elem(&active_conns, &call->key, &zero, BPF_ANY);
		stats = bpf_map_lookup_elem(&active_conns, &call->key);
	}

	if (!stats)
		return 0;

	stats->last_seen_ns = now;
	if (!stats->start_ns)
		stats->start_ns = now;
	if (!stats->cgroup_id)
		stats->cgroup_id = call->key.cgroup_id;
	if (call->current_state)
		stats->current_state = call->current_state;
	if (call->last_pid)
		stats->last_pid = call->last_pid;
	__builtin_memcpy(stats->comm, call->comm, sizeof(stats->comm));
	__sync_fetch_and_add(&stats->bytes_sent, bytes);
	return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(track_state_fentry, struct sock *sk, int state)
{
	return handle_state_change(sk, state);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(track_state_kprobe, struct sock *sk, int state)
{
	return handle_state_change(sk, state);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(track_send_fexit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
	return account_bytes(sk, ret > 0 ? ret : 0, 1);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(track_send_kprobe, struct sock *sk)
{
	struct sendmsg_call call = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (fill_conn_key(sk, &call.key) < 0)
		return 0;

	call.current_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	call.last_pid = pid_tgid >> 32;
	bpf_get_current_comm(call.comm, sizeof(call.comm));

	bpf_map_update_elem(&inflight_send, &pid_tgid, &call, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(track_send_kretprobe, int ret)
{
	struct sendmsg_call *call;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	call = bpf_map_lookup_elem(&inflight_send, &pid_tgid);
	if (!call)
		return 0;

	if (ret > 0)
		account_send_from_call(call, ret);

	bpf_map_delete_elem(&inflight_send, &pid_tgid);
	return 0;
}

SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(track_recv_fentry, struct sock *sk, int copied)
{
	return account_bytes(sk, copied > 0 ? copied : 0, 0);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(track_recv_kprobe, struct sock *sk, int copied)
{
	return account_bytes(sk, copied > 0 ? copied : 0, 0);
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(track_retransmit_fentry, struct sock *sk, struct sk_buff *skb, int segs)
{
	return account_retransmit(sk);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(track_retransmit_kprobe, struct sock *sk, struct sk_buff *skb, int segs)
{
	return account_retransmit(sk);
}
