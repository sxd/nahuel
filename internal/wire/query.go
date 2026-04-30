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

import (
	"strings"
	"unicode"
)

type Query struct {
	PID       uint32
	CgroupID  uint64
	Direction string
	Types     []string
}

func (q Query) Match(event Event) bool {
	if q.PID != 0 && event.PID != q.PID {
		return false
	}
	if q.CgroupID != 0 && event.CgroupID != q.CgroupID {
		return false
	}
	if q.Direction != "" {
		want := strings.ToLower(q.Direction)
		have := strings.ToLower(event.Direction.String())
		switch want {
		case "in", "ingress", "client", "client->server":
			if event.Direction != DirectionClientToServer {
				return false
			}
		case "out", "egress", "server", "server->client":
			if event.Direction != DirectionServerToClient {
				return false
			}
		default:
			if !strings.Contains(have, want) {
				return false
			}
		}
	}
	if len(q.Types) > 0 {
		have := normalizeMessageType(event.MessageType)
		matched := false
		for _, want := range q.Types {
			if normalizeMessageType(want) == have {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func normalizeMessageType(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}
