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

package main

import (
	"fmt"

	"nahuel/internal/correlator"
)

const defaultSessionHistoryLimit = 100

type sessionEventHistory struct {
	limit  int
	seen   map[string]struct{}
	events []correlator.ProtocolEvent
}

func newSessionEventHistory(limit int) *sessionEventHistory {
	if limit <= 0 {
		limit = defaultSessionHistoryLimit
	}
	return &sessionEventHistory{
		limit: limit,
		seen:  make(map[string]struct{}, limit),
	}
}

func (h *sessionEventHistory) Merge(in []correlator.ProtocolEvent) []correlator.ProtocolEvent {
	if len(in) == 0 {
		return append([]correlator.ProtocolEvent(nil), h.events...)
	}

	for i := len(in) - 1; i >= 0; i-- {
		event := in[i]
		key := sessionProtocolEventKey(event)
		if _, ok := h.seen[key]; ok {
			continue
		}
		h.seen[key] = struct{}{}
		h.events = append([]correlator.ProtocolEvent{event}, h.events...)
	}

	if len(h.events) > h.limit {
		excess := h.events[h.limit:]
		for _, event := range excess {
			delete(h.seen, sessionProtocolEventKey(event))
		}
		h.events = h.events[:h.limit]
	}

	return append([]correlator.ProtocolEvent(nil), h.events...)
}

func sessionProtocolEventKey(event correlator.ProtocolEvent) string {
	return fmt.Sprintf(
		"%d|%s|%s|%d|%d|%d|%s|%s|%s|%d|%s|%s",
		event.OccurredAt.UnixNano(),
		event.ConnectionID,
		event.ClientAddr,
		event.ClientPort,
		event.ServerPort,
		event.PID,
		event.Direction,
		event.API,
		event.MessageType,
		event.MessageLen,
		event.Detail,
		event.SQL,
	)
}
