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

package model

import "testing"

func TestAddressStringIPv4(t *testing.T) {
	var raw [16]byte
	raw[0] = 127
	raw[1] = 0
	raw[2] = 0
	raw[3] = 1

	if got := AddressString(2, raw); got != "127.0.0.1" {
		t.Fatalf("unexpected IPv4 string: %q", got)
	}
}

func TestTCPStateName(t *testing.T) {
	if got := TCPStateName(1); got != "ESTABLISHED" {
		t.Fatalf("unexpected TCP state: %q", got)
	}
	if got := TCPStateName(99); got != "STATE_99" {
		t.Fatalf("unexpected fallback TCP state: %q", got)
	}
}

func TestCloseReasonName(t *testing.T) {
	if got := CloseReasonName(2); got != "RESET" {
		t.Fatalf("unexpected close reason: %q", got)
	}
	if got := CloseReasonName(99); got != "UNKNOWN" {
		t.Fatalf("unexpected fallback close reason: %q", got)
	}
}
