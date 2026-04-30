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
	"testing"
	"time"

	"nahuel/internal/bpf"
)

type fakeBackend struct {
	mu         sync.Mutex
	samples    []bpf.Sample
	events     []bpf.ConnEvent
	attachMode string
	done       chan struct{}
}

func (f *fakeBackend) ListConnections() ([]bpf.Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]bpf.Sample, len(f.samples))
	copy(out, f.samples)
	return out, nil
}

func (f *fakeBackend) RunEventLoop(ctx context.Context, handle func(bpf.ConnEvent)) error {
	for _, event := range f.events {
		handle(event)
	}
	if f.done != nil {
		close(f.done)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeBackend) AttachMode() string {
	return f.attachMode
}

func TestCollectorSnapshotTracksRatesAndObserverStats(t *testing.T) {
	backend := &fakeBackend{
		attachMode: bpf.AttachModeTracing,
		done:       make(chan struct{}),
		samples: []bpf.Sample{
			{
				Key: bpf.ConnKey{
					Family:     2,
					ServerPort: 5432,
					ClientPort: 40000,
					Netns:      7,
					CgroupID:   99,
					ServerAddr: ipv4(10, 0, 0, 10),
					ClientAddr: ipv4(10, 0, 0, 5),
				},
				Stats: bpf.ConnStats{
					StartNs:    1,
					LastSeenNs: 1,
					BytesSent:  100,
					BytesRecv:  200,
					CgroupID:   99,
					LastPID:    123,
					Comm:       comm("postgres"),
				},
			},
		},
		events: []bpf.ConnEvent{
			{Type: bpf.EventEstablished},
			{Type: bpf.EventRetransmit},
			{
				Type: bpf.EventClosed,
				Key: bpf.ConnKey{
					Family:     2,
					ServerPort: 5432,
					ClientPort: 40000,
					Netns:      7,
					CgroupID:   99,
					ServerAddr: ipv4(10, 0, 0, 10),
					ClientAddr: ipv4(10, 0, 0, 5),
				},
				Stats: bpf.ConnStats{
					BytesSent:   100,
					BytesRecv:   200,
					CgroupID:    99,
					LastPID:     123,
					CloseReason: bpf.CloseFIN,
					Comm:        comm("postgres"),
				},
			},
		},
	}

	coll := New(backend)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coll.Start(ctx)
	<-backend.done

	first, err := coll.Snapshot()
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if first.Observer.AttachMode != bpf.AttachModeTracing {
		t.Fatalf("unexpected attach mode: %q", first.Observer.AttachMode)
	}
	if first.Observer.EstablishedEvents != 1 || first.Observer.RetransmitEvents != 1 || first.Observer.ClosedEvents != 1 {
		t.Fatalf("unexpected observer counts: %+v", first.Observer)
	}
	if len(first.Closed) != 1 {
		t.Fatalf("expected one closed connection, got %d", len(first.Closed))
	}
	if first.Connections[0].CgroupID != 99 {
		t.Fatalf("unexpected cgroup id: %d", first.Connections[0].CgroupID)
	}

	time.Sleep(20 * time.Millisecond)

	backend.mu.Lock()
	backend.samples[0].Stats.BytesSent = 300
	backend.samples[0].Stats.BytesRecv = 500
	backend.mu.Unlock()

	second, err := coll.Snapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if second.Connections[0].SendRate <= 0 || second.Connections[0].RecvRate <= 0 {
		t.Fatalf("expected positive rates, got tx=%f rx=%f", second.Connections[0].SendRate, second.Connections[0].RecvRate)
	}
}

func ipv4(a, b, c, d byte) [16]byte {
	var raw [16]byte
	raw[0] = a
	raw[1] = b
	raw[2] = c
	raw[3] = d
	return raw
}

func comm(text string) [16]byte {
	var out [16]byte
	copy(out[:], []byte(text))
	return out
}
