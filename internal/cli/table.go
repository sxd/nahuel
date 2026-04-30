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

package cli

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"nahuel/internal/branding"
	"nahuel/internal/model"
	"nahuel/internal/wire"
)

func RenderSnapshot(w io.Writer, command string, port uint16, snapshot model.Snapshot) {
	fmt.Fprintf(
		w,
		"%s %s %s  port=%d  attach=%s  captured=%s  events(established=%d closed=%d retransmit=%d dropped=%d)\n",
		branding.ExecutableName,
		branding.MonitorCommandName,
		command,
		port,
		snapshot.Observer.AttachMode,
		snapshot.CapturedAt.Format(time.RFC3339),
		snapshot.Observer.EstablishedEvents,
		snapshot.Observer.ClosedEvents,
		snapshot.Observer.RetransmitEvents,
		snapshot.Observer.DroppedEvents,
	)
	if snapshot.Observer.LastLoopError != "" {
		fmt.Fprintf(w, "event-loop-error=%s\n", snapshot.Observer.LastLoopError)
	}
	fmt.Fprintln(w)

	if len(snapshot.Connections) == 0 {
		fmt.Fprintln(w, "No active PostgreSQL connections observed.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT\tSERVER\tSTATE\tTX\tRX\tTX/s\tRX/s\tAGE\tIDLE\tRETX\tRST\tPID\tCOMM\tNETNS\tCGROUP")
		for _, conn := range snapshot.Connections {
			fmt.Fprintf(
				tw,
				"%s:%d\t%s:%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\n",
				conn.ClientAddr,
				conn.ClientPort,
				conn.ServerAddr,
				conn.ServerPort,
				conn.State,
				humanBytes(conn.BytesSent),
				humanBytes(conn.BytesRecv),
				humanRate(conn.SendRate),
				humanRate(conn.RecvRate),
				humanDuration(conn.Age),
				humanDuration(conn.Idle),
				conn.Retransmits,
				conn.Resets,
				conn.LastPID,
				conn.Command,
				conn.Netns,
				conn.CgroupID,
			)
		}
		_ = tw.Flush()
	}

	if len(snapshot.Closed) == 0 {
		return
	}

	fmt.Fprintln(w, "\nRecent closes")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tCLIENT\tSERVER\tLAST_STATE\tREASON\tTX\tRX\tRETX\tRST\tPID\tCOMM\tNETNS\tCGROUP")
	for _, conn := range snapshot.Closed {
		fmt.Fprintf(
			tw,
			"%s\t%s:%d\t%s:%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\n",
			conn.ClosedAt.Format("15:04:05"),
			conn.ClientAddr,
			conn.ClientPort,
			conn.ServerAddr,
			conn.ServerPort,
			conn.State,
			conn.CloseReason,
			humanBytes(conn.BytesSent),
			humanBytes(conn.BytesRecv),
			conn.Retransmits,
			conn.Resets,
			conn.LastPID,
			conn.Command,
			conn.Netns,
			conn.CgroupID,
		)
	}
	_ = tw.Flush()
}

func RenderEventsHeader(w io.Writer, port uint16, attachMode string) {
	fmt.Fprintf(w, "%s %s events  port=%d  attach=%s\n", branding.ExecutableName, branding.MonitorCommandName, port, attachMode)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tTYPE\tCLIENT\tSERVER\tSTATE\tREASON\tTX\tRX\tRETX\tRST\tPID\tCOMM\tNETNS\tCGROUP")
	_ = tw.Flush()
}

func RenderEvent(w io.Writer, event model.ConnectionEvent) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(
		tw,
		"%s\t%s\t%s:%d\t%s:%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\n",
		event.OccurredAt.Format("15:04:05"),
		event.Type,
		event.ClientAddr,
		event.ClientPort,
		event.ServerAddr,
		event.ServerPort,
		event.State,
		event.CloseReason,
		humanBytes(event.BytesSent),
		humanBytes(event.BytesRecv),
		event.Retransmits,
		event.Resets,
		event.LastPID,
		event.Command,
		event.Netns,
		event.CgroupID,
	)
	_ = tw.Flush()
}

func RenderWireHeader(w io.Writer, attachMode string, executables []string) {
	fmt.Fprintf(w, "%s %s  attach=%s\n", branding.ExecutableName, branding.WireCommandName, attachMode)
	if len(executables) > 0 {
		fmt.Fprintf(w, "executables=%s\n", stringsJoin(executables, ","))
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tPID\tCGROUP\tDIR\tAPI\tTYPE\tLEN\tUSER\tDB\tAPP\tDETAIL")
	_ = tw.Flush()
}

func RenderWireStatus(w io.Writer, chunks uint64, parsed uint64, rendered uint64, idle time.Duration) {
	state := "listening"
	if chunks == 0 {
		state = "waiting"
	}
	fmt.Fprintf(
		w,
		"status=%s chunks=%d parsed=%d rendered=%d idle=%s waiting for PostgreSQL protocol events\n",
		state,
		chunks,
		parsed,
		rendered,
		humanDuration(idle),
	)
}

func RenderWireEvent(w io.Writer, event wire.Event) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(
		tw,
		"%s\t%d\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
		event.OccurredAt.Format("15:04:05"),
		event.PID,
		event.CgroupID,
		event.Direction.String(),
		event.API.String(),
		event.Group.Label(),
		event.MessageType,
		event.MessageLen,
		emptyDash(event.Session.User),
		emptyDash(event.Session.Database),
		emptyDash(event.Session.Application),
		emptyDash(event.Summary),
	)
	_ = tw.Flush()
}

func humanBytes(v uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(v)
	unit := units[0]
	for i := 0; i < len(units)-1 && value >= 1024; i++ {
		value /= 1024
		unit = units[i+1]
	}
	if unit == "B" {
		return fmt.Sprintf("%dB", v)
	}
	return fmt.Sprintf("%.1f%s", value, unit)
}

func humanRate(v float64) string {
	return fmt.Sprintf("%s/s", humanBytes(uint64(v)))
}

func humanDuration(d time.Duration) string {
	if d < time.Second {
		return d.Truncate(time.Millisecond).String()
	}
	if d < time.Minute {
		return d.Truncate(time.Second).String()
	}
	if d < time.Hour {
		return d.Truncate(time.Second).String()
	}
	return d.Truncate(time.Minute).String()
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func stringsJoin(values []string, sep string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += sep + value
	}
	return out
}
