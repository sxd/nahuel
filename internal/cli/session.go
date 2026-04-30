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
	"nahuel/internal/correlator"
)

func RenderSessionSnapshot(w io.Writer, snapshot correlator.Snapshot) {
	fmt.Fprintf(
		w,
		"%s %s session  port=%d  net_attach=%s  %s_attach=%s  captured=%s  grouped_bytes=%s_plaintext\n",
		branding.ExecutableName,
		branding.MonitorCommandName,
		snapshot.Port,
		snapshot.NetworkObserver.AttachMode,
		branding.WireCommandName,
		snapshot.WireAttachMode,
		snapshot.CapturedAt.Format(time.RFC3339),
		branding.WireCommandName,
	)
	fmt.Fprintf(
		w,
		"network_events(established=%d closed=%d retransmit=%d dropped=%d)\n",
		snapshot.NetworkObserver.EstablishedEvents,
		snapshot.NetworkObserver.ClosedEvents,
		snapshot.NetworkObserver.RetransmitEvents,
		snapshot.NetworkObserver.DroppedEvents,
	)
	if snapshot.NetworkObserver.LastLoopError != "" {
		fmt.Fprintf(w, "network_event_loop_error=%s\n", snapshot.NetworkObserver.LastLoopError)
	}
	if len(snapshot.WireExecutables) > 0 {
		fmt.Fprintf(w, "%s_executables=%s\n", branding.WireCommandName, stringsJoin(snapshot.WireExecutables, ","))
	}
	fmt.Fprintln(w)

	if len(snapshot.Connections) == 0 {
		fmt.Fprintln(w, "No active PostgreSQL sessions observed.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT\tSERVER\tSTATE\tTX\tRX\tSQL_TX\tSQL_RX\tCFG_TX\tCFG_RX\tWAL_TX\tWAL_RX\tPID\tUSER\tDB\tAPP\tLAST")
		for _, view := range snapshot.Connections {
			fmt.Fprintf(
				tw,
				"%s:%d\t%s:%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				view.Connection.ClientAddr,
				view.Connection.ClientPort,
				view.Connection.ServerAddr,
				view.Connection.ServerPort,
				view.Connection.State,
				humanBytes(view.Connection.BytesSent),
				humanBytes(view.Connection.BytesRecv),
				humanBytes(view.QueriesSQL.TxBytes),
				humanBytes(view.QueriesSQL.RxBytes),
				humanBytes(view.Config.TxBytes),
				humanBytes(view.Config.RxBytes),
				humanBytes(view.WAL.TxBytes),
				humanBytes(view.WAL.RxBytes),
				view.Connection.LastPID,
				emptyDash(view.Session.User),
				emptyDash(view.Session.Database),
				emptyDash(view.Session.Application),
				emptyDash(lastProtocolSummary(view)),
			)
		}
		_ = tw.Flush()
	}

	if len(snapshot.Recent) == 0 {
		return
	}

	fmt.Fprintln(w, "\nProtocol activity log (newest first)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tCLIENT\tSERVER\tGROUP\tDIR\tTYPE\tLEN\tPID\tUSER\tDB\tDETAIL")
	for _, event := range snapshot.Recent {
		fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			event.OccurredAt.Format("15:04:05"),
			endpointOrDash(event.ClientAddr, event.ClientPort),
			endpointOrDash(event.ServerAddr, event.ServerPort),
			event.Group.Label(),
			event.Direction,
			event.MessageType,
			event.MessageLen,
			event.PID,
			emptyDash(event.User),
			emptyDash(event.Database),
			emptyDash(event.Detail),
		)
	}
	_ = tw.Flush()
}

func endpointOrDash(address string, port uint16) string {
	if address == "" {
		return "-"
	}
	return fmt.Sprintf("%s:%d", address, port)
}

func lastProtocolSummary(view correlator.ConnectionView) string {
	if view.LastType == "" {
		return ""
	}
	if view.LastGroup == "" {
		return view.LastType
	}
	return fmt.Sprintf("%s/%s", view.LastGroup, view.LastType)
}
