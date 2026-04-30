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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"nahuel/internal/bpf"
	"nahuel/internal/branding"
	"nahuel/internal/cli"
	"nahuel/internal/collector"
	"nahuel/internal/model"
	"nahuel/internal/wire"
)

type outputMode string

const (
	outputText outputMode = "text"
	outputJSON outputMode = "json"
)

func main() {
	group, command, args := parseCommand(os.Args[1:])
	if err := run(group, command, args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(group string, command string, args []string) error {
	switch group {
	case "help":
		printUsage(os.Stdout)
		return nil
	case branding.MonitorCommandName:
		switch command {
		case "watch", "top", "events":
			return runConnectionCommand(command, args)
		case "session":
			return runSessionCommand(args)
		case "help", "":
			printMonitorUsage(os.Stdout)
			return nil
		default:
			return fmt.Errorf("unsupported %s command %q; supported commands: watch, top, events, session", branding.MonitorCommandName, command)
		}
	case branding.WireCommandName:
		if command == "help" {
			printWireUsage(os.Stdout)
			return nil
		}
		return runWireCommand(args)
	default:
		return fmt.Errorf("unsupported command %q; supported top-level commands: %s, %s", group, branding.MonitorCommandName, branding.WireCommandName)
	}
}

func runConnectionCommand(command string, args []string) error {
	fs := flag.NewFlagSet(branding.ExecutableName+" "+branding.MonitorCommandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Uint("port", 5432, "PostgreSQL port to observe")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval for watch")
	noClear := fs.Bool("no-clear", false, "disable terminal clear between watch updates")
	output := fs.String("output", string(outputText), "render format: text, json")
	client := fs.String("client", "", "filter by client address or address:port substring")
	server := fs.String("server", "", "filter by server address or address:port substring")
	pid := fs.Uint("pid", 0, "filter by process ID")
	netns := fs.Uint("netns", 0, "filter by network namespace inode")
	cgroupID := fs.Uint64("cgroup", 0, "filter by cgroup identifier")
	limit := fs.Int("limit", 0, "limit rendered rows or number of events")
	sortKey := fs.String("sort", "rate", "connection sort order: rate, tx, rx, age, retransmits")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printMonitorUsage(os.Stdout)
			return nil
		}
		return fmt.Errorf("parse flags: %w", err)
	}

	format, err := parseOutputMode(*output)
	if err != nil {
		return err
	}

	query := model.Query{
		Client:   *client,
		Server:   *server,
		PID:      uint32(*pid),
		Netns:    uint32(*netns),
		CgroupID: *cgroupID,
		Limit:    *limit,
		Sort:     *sortKey,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runtime, err := bpf.Open(uint16(*port))
	if err != nil {
		return fmt.Errorf("failed to start BPF runtime: %v\nrun as root or with the capabilities required to load tracing/kprobe eBPF programs", err)
	}
	defer func() {
		_ = runtime.Close()
	}()

	coll := collector.New(runtime)

	switch command {
	case "top":
		return renderSnapshot("top", coll, uint16(*port), query, false, format)
	case "watch":
		coll.Start(ctx)
		return runWatch(ctx, coll, uint16(*port), *interval, !*noClear, query, format)
	case "events":
		events, cancel := coll.Subscribe(256)
		defer cancel()
		coll.Start(ctx)
		return runEvents(ctx, runtime.AttachMode(), uint16(*port), events, query, format)
	default:
		return fmt.Errorf("unsupported %s command %q", branding.MonitorCommandName, command)
	}
}

func runWireCommand(args []string) error {
	fs := flag.NewFlagSet(branding.ExecutableName+" "+branding.WireCommandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pid := fs.Uint("pid", 0, "filter by PostgreSQL backend PID")
	cgroupID := fs.Uint64("cgroup", 0, "filter by cgroup identifier")
	direction := fs.String("direction", "", "filter by direction: in, out, client->server, server->client")
	output := fs.String("output", string(outputText), "render format: text, json")
	var messageTypes stringListFlag
	fs.Var(&messageTypes, "type", "filter by PostgreSQL message type; repeat the flag or use a comma-separated list")
	detailLimit := fs.Int("detail-limit", 0, "max characters to render in PostgreSQL message details (0 = unlimited)")
	captureBytes := fs.Uint("capture-bytes", wire.DefaultCaptureBytes, "effective plaintext byte limit per traced PostgreSQL read/write call (max 4096)")
	waitForPostgres := fs.Bool("wait-for-postgres", false, "keep running and attach when PostgreSQL processes appear")
	scanInterval := fs.Duration("scan-interval", wire.DefaultScanInterval, "how often to rescan for PostgreSQL executables when waiting")
	limit := fs.Int("limit", 0, "stop after rendering N parsed protocol events")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printWireUsage(os.Stdout)
			return nil
		}
		return fmt.Errorf("parse %s flags: %w", branding.WireCommandName, err)
	}

	format, err := parseOutputMode(*output)
	if err != nil {
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	runtime, err := wire.Open(wire.Options{
		CaptureBytes:    uint32(*captureBytes),
		WaitForPostgres: *waitForPostgres,
		ScanInterval:    *scanInterval,
	})
	if err != nil {
		return fmt.Errorf("failed to start %s runtime: %w", branding.WireCommandName, err)
	}
	defer func() {
		_ = runtime.Close()
	}()

	query := wire.Query{
		PID:       uint32(*pid),
		CgroupID:  *cgroupID,
		Direction: *direction,
		Types:     append([]string(nil), messageTypes...),
	}
	parser := wire.NewParser(*detailLimit)
	if format == outputText {
		cli.RenderWireHeader(os.Stdout, runtime.AttachMode(), runtime.Executables())
		cli.RenderWireStatus(os.Stdout, 0, 0, 0, 0)
	} else {
		if err := cli.RenderWireStatusJSON(os.Stdout, runtime.AttachMode(), runtime.Executables(), 0, 0, 0, 0); err != nil {
			return err
		}
	}

	chunksCh := make(chan wire.Chunk, 256)
	loopErrCh := make(chan error, 1)
	go func() {
		loopErrCh <- runtime.RunEventLoop(ctx, func(chunk wire.Chunk) {
			select {
			case chunksCh <- chunk:
			case <-ctx.Done():
			}
		})
		close(chunksCh)
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var (
		chunksSeen   uint64
		parsedEvents uint64
		printed      uint64
		lastActivity = time.Now()
	)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-loopErrCh:
			if err != nil {
				return err
			}
			return nil
		case chunk, ok := <-chunksCh:
			if !ok {
				return nil
			}

			chunksSeen++
			lastActivity = time.Now()

			events := parser.Feed(chunk)
			parsedEvents += uint64(len(events))
			for _, event := range events {
				if !query.Match(event) {
					continue
				}
				if format == outputText {
					cli.RenderWireEvent(os.Stdout, event)
				} else if err := cli.RenderWireEventJSON(os.Stdout, runtime.AttachMode(), event); err != nil {
					return err
				}
				printed++
				if *limit > 0 && printed >= uint64(*limit) {
					cancel()
					return nil
				}
			}
		case <-ticker.C:
			if format == outputText {
				cli.RenderWireStatus(os.Stdout, chunksSeen, parsedEvents, printed, time.Since(lastActivity))
			} else if err := cli.RenderWireStatusJSON(os.Stdout, runtime.AttachMode(), runtime.Executables(), chunksSeen, parsedEvents, printed, time.Since(lastActivity)); err != nil {
				return err
			}
		}
	}
}

func runWatch(ctx context.Context, coll *collector.Collector, port uint16, interval time.Duration, clear bool, query model.Query, format outputMode) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := renderSnapshot("watch", coll, port, query, clear, format); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			if format == outputText {
				fmt.Println()
			}
			return nil
		case <-ticker.C:
			if err := renderSnapshot("watch", coll, port, query, clear, format); err != nil {
				return err
			}
		}
	}
}

func runEvents(ctx context.Context, attachMode string, port uint16, events <-chan model.ConnectionEvent, query model.Query, format outputMode) error {
	if format == outputText {
		cli.RenderEventsHeader(os.Stdout, port, attachMode)
	}

	printed := 0
	for {
		select {
		case <-ctx.Done():
			if format == outputText {
				fmt.Println()
			}
			return nil
		case event, ok := <-events:
			if !ok {
				return nil
			}
			if !query.MatchEvent(event) {
				continue
			}
			if format == outputText {
				cli.RenderEvent(os.Stdout, event)
			} else if err := cli.RenderConnectionEventJSON(os.Stdout, port, attachMode, event); err != nil {
				return err
			}
			printed++
			if query.Limit > 0 && printed >= query.Limit {
				return nil
			}
		}
	}
}

func renderSnapshot(command string, coll *collector.Collector, port uint16, query model.Query, clear bool, format outputMode) error {
	snapshot, err := coll.Snapshot()
	if err != nil {
		return err
	}

	filtered := query.ApplySnapshot(snapshot)
	if format == outputText {
		if clear {
			fmt.Print("\x1b[H\x1b[2J")
		}
		cli.RenderSnapshot(os.Stdout, command, port, filtered)
		return nil
	}
	return cli.RenderSnapshotJSON(os.Stdout, command, port, filtered)
}

func parseCommand(args []string) (string, string, []string) {
	if len(args) == 0 {
		return "help", "", nil
	}

	first := args[0]
	if isHelpToken(first) {
		return "help", "", nil
	}

	switch first {
	case branding.MonitorCommandName:
		return parseMonitorCommand(args[1:])
	case branding.WireCommandName:
		if len(args) > 1 && isHelpToken(args[1]) {
			return branding.WireCommandName, "help", nil
		}
		return branding.WireCommandName, "", args[1:]
	case "watch", "top", "events", "session":
		return branding.MonitorCommandName, first, args[1:]
	default:
		if strings.HasPrefix(first, "-") {
			return branding.MonitorCommandName, "watch", args
		}
		return first, "", args[1:]
	}
}

func parseMonitorCommand(args []string) (string, string, []string) {
	if len(args) == 0 {
		return branding.MonitorCommandName, "help", nil
	}
	if isHelpToken(args[0]) {
		return branding.MonitorCommandName, "help", nil
	}
	if strings.HasPrefix(args[0], "-") {
		return branding.MonitorCommandName, "watch", args
	}
	return branding.MonitorCommandName, args[0], args[1:]
}

func isHelpToken(value string) bool {
	switch value {
	case "help", "-h", "--help":
		return true
	default:
		return false
	}
}

func parseOutputMode(value string) (outputMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(outputText):
		return outputText, nil
	case string(outputJSON):
		return outputJSON, nil
	default:
		return "", fmt.Errorf("unsupported output mode %q; supported values: text, json", value)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage:\n  %s %s <watch|top|events|session> [flags]\n  %s %s [flags]\n\n", branding.ExecutableName, branding.MonitorCommandName, branding.ExecutableName, branding.WireCommandName)
	printMonitorUsage(w)
	printWireUsage(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run as root or with the capabilities required to load BPF programs.")
}

func printMonitorUsage(w io.Writer) {
	fmt.Fprintf(w, "  %s %s watch [-port 5432] [-interval 2s] [-no-clear] [-output text|json] [-client FILTER] [-server FILTER] [-pid PID] [-netns NS] [-cgroup ID] [-limit N] [-sort rate|tx|rx|age|retransmits]\n", branding.ExecutableName, branding.MonitorCommandName)
	fmt.Fprintf(w, "  %s %s top [-port 5432] [-output text|json] [-client FILTER] [-server FILTER] [-pid PID] [-netns NS] [-cgroup ID] [-limit N] [-sort rate|tx|rx|age|retransmits]\n", branding.ExecutableName, branding.MonitorCommandName)
	fmt.Fprintf(w, "  %s %s events [-port 5432] [-output text|json] [-client FILTER] [-server FILTER] [-pid PID] [-netns NS] [-cgroup ID] [-limit N]\n", branding.ExecutableName, branding.MonitorCommandName)
	fmt.Fprintf(w, "  %s %s session [-port 5432] [-interval 2s] [-no-clear] [-output text|json] [-client FILTER] [-server FILTER] [-pid PID] [-netns NS] [-cgroup ID] [-limit N] [-sort rate|tx|rx|age|retransmits] [-recent N] [-detail-limit N] [-capture-bytes N] [-wait-for-postgres] [-scan-interval DURATION]\n", branding.ExecutableName, branding.MonitorCommandName)
}

func printWireUsage(w io.Writer) {
	fmt.Fprintf(w, "  %s %s [-pid PID] [-cgroup ID] [-direction in|out] [-type NAME[,NAME...]]... [-output text|json] [-detail-limit N] [-capture-bytes N] [-wait-for-postgres] [-scan-interval DURATION] [-limit N]\n", branding.ExecutableName, branding.WireCommandName)
	fmt.Fprintln(w, "    type matching is exact and case-insensitive, for example: -type Query,ReadyForQuery")
	fmt.Fprintln(w, "    detail-limit defaults to 0 (unlimited); capture-bytes defaults to 4096 and clamps rendered/parser input")
}

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	added := false
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*f = append(*f, part)
		added = true
	}
	if !added {
		return fmt.Errorf("empty value")
	}
	return nil
}
