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

import "testing"

func TestParseCommandDefaultsToMonitorWatchForFlags(t *testing.T) {
	group, command, args := parseCommand([]string{"-port", "5432"})
	if group != "mon" || command != "watch" {
		t.Fatalf("expected mon/watch, got %q/%q", group, command)
	}
	if len(args) != 2 {
		t.Fatalf("unexpected args length: %d", len(args))
	}
}

func TestParseCommandMonitorEvents(t *testing.T) {
	group, command, args := parseCommand([]string{"mon", "events", "-limit", "5"})
	if group != "mon" || command != "events" {
		t.Fatalf("expected mon/events, got %q/%q", group, command)
	}
	if len(args) != 2 || args[0] != "-limit" || args[1] != "5" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseCommandWire(t *testing.T) {
	group, command, args := parseCommand([]string{"wire", "-pid", "4321"})
	if group != "wire" || command != "" {
		t.Fatalf("expected wire, got %q/%q", group, command)
	}
	if len(args) != 2 || args[0] != "-pid" || args[1] != "4321" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseCommandSessionCompatibility(t *testing.T) {
	group, command, args := parseCommand([]string{"session", "-pid", "4321"})
	if group != "mon" || command != "session" {
		t.Fatalf("expected mon/session, got %q/%q", group, command)
	}
	if len(args) != 2 || args[0] != "-pid" || args[1] != "4321" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseOutputModeText(t *testing.T) {
	mode, err := parseOutputMode("text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != outputText {
		t.Fatalf("expected text mode, got %q", mode)
	}
}

func TestParseOutputModeJSON(t *testing.T) {
	mode, err := parseOutputMode("json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != outputJSON {
		t.Fatalf("expected json mode, got %q", mode)
	}
}

func TestParseOutputModeRejectsUnknown(t *testing.T) {
	if _, err := parseOutputMode("yaml"); err == nil {
		t.Fatal("expected error for unknown output mode")
	}
}
