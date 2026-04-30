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

package collector

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"nahuel/internal/bpf"
	"nahuel/internal/model"
)

type Backend interface {
	ListConnections() ([]bpf.Sample, error)
	RunEventLoop(context.Context, func(bpf.ConnEvent)) error
	AttachMode() string
}

type previousSample struct {
	at        time.Time
	bytesSent uint64
	bytesRecv uint64
}

type Collector struct {
	runtime Backend

	mu          sync.Mutex
	previous    map[string]previousSample
	recentDone  []model.ClosedConnection
	recentEvent []model.ConnectionEvent
	subscribers map[chan model.ConnectionEvent]struct{}
	observer    model.ObserverStats
}

func New(runtime Backend) *Collector {
	return &Collector{
		runtime:     runtime,
		previous:    make(map[string]previousSample),
		subscribers: make(map[chan model.ConnectionEvent]struct{}),
		observer: model.ObserverStats{
			AttachMode: runtime.AttachMode(),
		},
	}
}

func (c *Collector) Start(ctx context.Context) {
	go func() {
		if err := c.runtime.RunEventLoop(ctx, c.handleEvent); err != nil {
			c.mu.Lock()
			c.observer.LastLoopError = err.Error()
			c.mu.Unlock()
		}
	}()
}

func (c *Collector) Snapshot() (model.Snapshot, error) {
	now := time.Now()
	nowMono, err := monotonicNow()
	if err != nil {
		return model.Snapshot{}, err
	}

	samples, err := c.runtime.ListConnections()
	if err != nil {
		return model.Snapshot{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	connections := make([]model.Connection, 0, len(samples))
	seen := make(map[string]struct{}, len(samples))

	for _, sample := range samples {
		clientAddr := model.AddressString(sample.Key.Family, sample.Key.ClientAddr)
		serverAddr := model.AddressString(sample.Key.Family, sample.Key.ServerAddr)
		id := model.ConnectionID(sample.Key.Family, clientAddr, sample.Key.ClientPort, serverAddr, sample.Key.ServerPort, sample.Key.Netns, sample.Key.CgroupID)

		var sendRate float64
		var recvRate float64
		if prev, ok := c.previous[id]; ok {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed > 0 {
				sendRate = float64(sample.Stats.BytesSent-prev.bytesSent) / elapsed
				recvRate = float64(sample.Stats.BytesRecv-prev.bytesRecv) / elapsed
			}
		}

		connections = append(connections, model.Connection{
			ID:          id,
			ClientAddr:  clientAddr,
			ClientPort:  sample.Key.ClientPort,
			ServerAddr:  serverAddr,
			ServerPort:  sample.Key.ServerPort,
			Netns:       sample.Key.Netns,
			CgroupID:    sample.Stats.CgroupID,
			State:       model.TCPStateName(sample.Stats.CurrentState),
			BytesSent:   sample.Stats.BytesSent,
			BytesRecv:   sample.Stats.BytesRecv,
			SendRate:    sendRate,
			RecvRate:    recvRate,
			Retransmits: sample.Stats.Retransmits,
			Resets:      sample.Stats.Resets,
			Age:         durationFromMonotonic(nowMono, sample.Stats.StartNs),
			Idle:        durationFromMonotonic(nowMono, sample.Stats.LastSeenNs),
			LastPID:     sample.Stats.LastPID,
			Command:     model.CommString(sample.Stats.Comm),
		})

		c.previous[id] = previousSample{
			at:        now,
			bytesSent: sample.Stats.BytesSent,
			bytesRecv: sample.Stats.BytesRecv,
		}
		seen[id] = struct{}{}
	}

	for id := range c.previous {
		if _, ok := seen[id]; !ok {
			delete(c.previous, id)
		}
	}

	closed := append([]model.ClosedConnection(nil), c.recentDone...)
	return model.Snapshot{
		CapturedAt:  now,
		Connections: connections,
		Closed:      closed,
		Observer:    c.observer,
	}, nil
}

func (c *Collector) RecentEvents(limit int) []model.ConnectionEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	events := append([]model.ConnectionEvent(nil), c.recentEvent...)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events
}

func (c *Collector) Subscribe(buffer int) (<-chan model.ConnectionEvent, func()) {
	if buffer <= 0 {
		buffer = 1
	}

	ch := make(chan model.ConnectionEvent, buffer)

	c.mu.Lock()
	c.subscribers[ch] = struct{}{}
	c.mu.Unlock()

	cancel := func() {
		c.mu.Lock()
		if _, ok := c.subscribers[ch]; ok {
			delete(c.subscribers, ch)
			close(ch)
		}
		c.mu.Unlock()
	}

	return ch, cancel
}

func (c *Collector) handleEvent(event bpf.ConnEvent) {
	converted := model.ConnectionEvent{
		Type:        eventTypeName(event.Type),
		ClientAddr:  model.AddressString(event.Key.Family, event.Key.ClientAddr),
		ClientPort:  event.Key.ClientPort,
		ServerAddr:  model.AddressString(event.Key.Family, event.Key.ServerAddr),
		ServerPort:  event.Key.ServerPort,
		Netns:       event.Key.Netns,
		CgroupID:    event.Stats.CgroupID,
		State:       model.TCPStateName(event.NewState),
		CloseReason: model.CloseReasonName(event.Stats.CloseReason),
		BytesSent:   event.Stats.BytesSent,
		BytesRecv:   event.Stats.BytesRecv,
		Retransmits: event.Stats.Retransmits,
		Resets:      event.Stats.Resets,
		LastPID:     event.Stats.LastPID,
		Command:     model.CommString(event.Stats.Comm),
		OccurredAt:  time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.Type {
	case bpf.EventEstablished:
		c.observer.EstablishedEvents++
	case bpf.EventClosed:
		c.observer.ClosedEvents++
	case bpf.EventRetransmit:
		c.observer.RetransmitEvents++
	}

	c.recentEvent = append([]model.ConnectionEvent{converted}, c.recentEvent...)
	if len(c.recentEvent) > 100 {
		c.recentEvent = c.recentEvent[:100]
	}

	if event.Type == bpf.EventClosed {
		entry := model.ClosedConnection{
			ClientAddr:  converted.ClientAddr,
			ClientPort:  converted.ClientPort,
			ServerAddr:  converted.ServerAddr,
			ServerPort:  converted.ServerPort,
			Netns:       converted.Netns,
			CgroupID:    converted.CgroupID,
			State:       model.TCPStateName(event.OldState),
			CloseReason: converted.CloseReason,
			BytesSent:   converted.BytesSent,
			BytesRecv:   converted.BytesRecv,
			Retransmits: converted.Retransmits,
			Resets:      converted.Resets,
			LastPID:     converted.LastPID,
			Command:     converted.Command,
			ClosedAt:    converted.OccurredAt,
		}

		c.recentDone = append([]model.ClosedConnection{entry}, c.recentDone...)
		if len(c.recentDone) > 20 {
			c.recentDone = c.recentDone[:20]
		}
	}

	for subscriber := range c.subscribers {
		select {
		case subscriber <- converted:
		default:
			c.observer.DroppedEvents++
		}
	}
}

func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}

func durationFromMonotonic(now uint64, then uint64) time.Duration {
	if then == 0 || now < then {
		return 0
	}
	return time.Duration(now - then)
}

func eventTypeName(kind uint32) string {
	switch kind {
	case bpf.EventEstablished:
		return "ESTABLISHED"
	case bpf.EventClosed:
		return "CLOSED"
	case bpf.EventRetransmit:
		return "RETRANSMIT"
	default:
		return "UNKNOWN"
	}
}
