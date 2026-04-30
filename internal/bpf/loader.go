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

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	EventEstablished = 1
	EventClosed      = 2
	EventRetransmit  = 3

	CloseUnknown = 0
	CloseFIN     = 1
	CloseReset   = 2
	CloseTimeout = 3
	CloseAbort   = 4

	AttachModeTracing = "tracing"
	AttachModeKprobe  = "kprobe"
)

type ConnKey struct {
	Family     uint16
	ServerPort uint16
	ClientPort uint16
	Pad        uint16
	Netns      uint32
	Reserved   uint32
	CgroupID   uint64
	ServerAddr [16]byte
	ClientAddr [16]byte
}

type ConnStats struct {
	StartNs      uint64
	LastSeenNs   uint64
	BytesSent    uint64
	BytesRecv    uint64
	Retransmits  uint64
	Resets       uint64
	CgroupID     uint64
	LastPID      uint32
	CurrentState uint32
	LastError    int32
	CloseReason  uint32
	Comm         [16]byte
}

type ConnEvent struct {
	Key         ConnKey
	Stats       ConnStats
	TimestampNs uint64
	Type        uint32
	OldState    uint32
	NewState    uint32
	Pad         uint32
}

type Sample struct {
	Key   ConnKey
	Stats ConnStats
}

type runtimeMaps struct {
	ActiveConns *ebpf.Map `ebpf:"active_conns"`
	ConnEvents  *ebpf.Map `ebpf:"conn_events"`
}

type tracingObjects struct {
	runtimeMaps
	TrackRecvFentry       *ebpf.Program `ebpf:"track_recv_fentry"`
	TrackRetransmitFentry *ebpf.Program `ebpf:"track_retransmit_fentry"`
	TrackSendFexit        *ebpf.Program `ebpf:"track_send_fexit"`
	TrackStateFentry      *ebpf.Program `ebpf:"track_state_fentry"`
}

func (o *tracingObjects) Close() error {
	return closeAll(
		o.TrackRecvFentry,
		o.TrackRetransmitFentry,
		o.TrackSendFexit,
		o.TrackStateFentry,
		o.ActiveConns,
		o.ConnEvents,
	)
}

type kprobeObjects struct {
	runtimeMaps
	InflightSend          *ebpf.Map     `ebpf:"inflight_send"`
	TrackRecvKprobe       *ebpf.Program `ebpf:"track_recv_kprobe"`
	TrackRetransmitKprobe *ebpf.Program `ebpf:"track_retransmit_kprobe"`
	TrackSendKprobe       *ebpf.Program `ebpf:"track_send_kprobe"`
	TrackSendKretprobe    *ebpf.Program `ebpf:"track_send_kretprobe"`
	TrackStateKprobe      *ebpf.Program `ebpf:"track_state_kprobe"`
}

func (o *kprobeObjects) Close() error {
	return closeAll(
		o.TrackRecvKprobe,
		o.TrackRetransmitKprobe,
		o.TrackSendKprobe,
		o.TrackSendKretprobe,
		o.TrackStateKprobe,
		o.ActiveConns,
		o.ConnEvents,
		o.InflightSend,
	)
}

type Runtime struct {
	activeConns *ebpf.Map
	connEvents  *ebpf.Map
	reader      *ringbuf.Reader
	links       []link.Link
	closer      io.Closer
	attachMode  string
}

var (
	memlockOnce sync.Once
	memlockErr  error
)

func Open(port uint16) (*Runtime, error) {
	memlockOnce.Do(func() {
		memlockErr = rlimit.RemoveMemlock()
	})
	if memlockErr != nil && !errors.Is(memlockErr, unix.EPERM) {
		return nil, fmt.Errorf("remove memlock rlimit: %w", memlockErr)
	}

	tracingRuntime, tracingErr := openTracing(port)
	if tracingErr == nil {
		return tracingRuntime, nil
	}

	kprobeRuntime, kprobeErr := openKprobe(port)
	if kprobeErr == nil {
		return kprobeRuntime, nil
	}

	return nil, fmt.Errorf("tracing mode failed: %v; kprobe mode failed: %w", tracingErr, kprobeErr)
}

func (rt *Runtime) AttachMode() string {
	return rt.attachMode
}

func (rt *Runtime) ListConnections() ([]Sample, error) {
	var (
		key   ConnKey
		stats ConnStats
		items []Sample
	)

	iter := rt.activeConns.Iterate()
	for iter.Next(&key, &stats) {
		items = append(items, Sample{Key: key, Stats: stats})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate active connections: %w", err)
	}

	return items, nil
}

func (rt *Runtime) RunEventLoop(ctx context.Context, handle func(ConnEvent)) error {
	for {
		record, err := rt.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		var event ConnEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode event: %w", err)
		}
		handle(event)
	}
}

func (rt *Runtime) Close() error {
	if rt.reader != nil {
		_ = rt.reader.Close()
	}

	closeLinks(rt.links)
	rt.links = nil

	if rt.closer != nil {
		return rt.closer.Close()
	}
	return nil
}

func openTracing(port uint16) (*Runtime, error) {
	spec, err := loadPreparedSpec(port)
	if err != nil {
		return nil, err
	}

	var objs tracingObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tracing objects: %w", err)
	}

	rt := &Runtime{
		activeConns: objs.ActiveConns,
		connEvents:  objs.ConnEvents,
		closer:      &objs,
		attachMode:  AttachModeTracing,
	}

	if err := rt.attachTracing(&objs); err != nil {
		rt.Close()
		return nil, fmt.Errorf("attach tracing objects: %w", err)
	}

	if err := rt.openReader(); err != nil {
		rt.Close()
		return nil, err
	}

	return rt, nil
}

func openKprobe(port uint16) (*Runtime, error) {
	spec, err := loadPreparedSpec(port)
	if err != nil {
		return nil, err
	}

	var objs kprobeObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load kprobe objects: %w", err)
	}

	rt := &Runtime{
		activeConns: objs.ActiveConns,
		connEvents:  objs.ConnEvents,
		closer:      &objs,
		attachMode:  AttachModeKprobe,
	}

	if err := rt.attachKprobes(&objs); err != nil {
		rt.Close()
		return nil, fmt.Errorf("attach kprobe objects: %w", err)
	}

	if err := rt.openReader(); err != nil {
		rt.Close()
		return nil, err
	}

	return rt, nil
}

func loadPreparedSpec(port uint16) (*ebpf.CollectionSpec, error) {
	spec, err := loadNetmon()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	variable, ok := spec.Variables["target_port"]
	if !ok {
		return nil, fmt.Errorf("missing BPF variable %q", "target_port")
	}
	if err := variable.Set(port); err != nil {
		return nil, fmt.Errorf("set BPF variable %q: %w", "target_port", err)
	}

	return spec, nil
}

func (rt *Runtime) attachTracing(objs *tracingObjects) error {
	links := make([]link.Link, 0, 4)
	attach := func(prog *ebpf.Program) error {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	if err := attach(objs.TrackStateFentry); err != nil {
		closeLinks(links)
		return err
	}
	if err := attach(objs.TrackSendFexit); err != nil {
		closeLinks(links)
		return err
	}
	if err := attach(objs.TrackRecvFentry); err != nil {
		closeLinks(links)
		return err
	}
	if err := attach(objs.TrackRetransmitFentry); err != nil {
		closeLinks(links)
		return err
	}

	rt.links = append(rt.links, links...)
	return nil
}

func (rt *Runtime) attachKprobes(objs *kprobeObjects) error {
	links := make([]link.Link, 0, 5)

	kprobe, err := link.Kprobe("tcp_set_state", objs.TrackStateKprobe, nil)
	if err != nil {
		closeLinks(links)
		return err
	}
	links = append(links, kprobe)

	kprobe, err = link.Kprobe("tcp_sendmsg", objs.TrackSendKprobe, nil)
	if err != nil {
		closeLinks(links)
		return err
	}
	links = append(links, kprobe)

	kretprobe, err := link.Kretprobe("tcp_sendmsg", objs.TrackSendKretprobe, nil)
	if err != nil {
		closeLinks(links)
		return err
	}
	links = append(links, kretprobe)

	kprobe, err = link.Kprobe("tcp_cleanup_rbuf", objs.TrackRecvKprobe, nil)
	if err != nil {
		closeLinks(links)
		return err
	}
	links = append(links, kprobe)

	kprobe, err = link.Kprobe("tcp_retransmit_skb", objs.TrackRetransmitKprobe, nil)
	if err != nil {
		closeLinks(links)
		return err
	}
	links = append(links, kprobe)

	rt.links = append(rt.links, links...)
	return nil
}

func (rt *Runtime) openReader() error {
	reader, err := ringbuf.NewReader(rt.connEvents)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	rt.reader = reader
	return nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func closeAll(closers ...io.Closer) error {
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
