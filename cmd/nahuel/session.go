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
	"syscall"
	"time"

	"nahuel/internal/bpf"
	"nahuel/internal/branding"
	"nahuel/internal/cli"
	"nahuel/internal/collector"
	"nahuel/internal/correlator"
	"nahuel/internal/model"
	"nahuel/internal/wire"
)

func runSessionCommand(args []string) error {
	fs := flag.NewFlagSet(branding.ExecutableName+" "+branding.MonitorCommandName+" session", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Uint("port", 5432, "PostgreSQL port to observe")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval")
	noClear := fs.Bool("no-clear", false, "disable terminal clear between refreshes")
	output := fs.String("output", string(outputText), "render format: text, json")
	client := fs.String("client", "", "filter by client address or address:port substring")
	server := fs.String("server", "", "filter by server address or address:port substring")
	pid := fs.Uint("pid", 0, "filter by process ID")
	netns := fs.Uint("netns", 0, "filter by network namespace inode")
	cgroupID := fs.Uint64("cgroup", 0, "filter by cgroup identifier")
	limit := fs.Int("limit", 0, "limit rendered rows and recent protocol events")
	sortKey := fs.String("sort", "rate", "connection sort order: rate, tx, rx, age, retransmits")
	recent := fs.Int("recent", 20, "recent protocol events to render")
	detailLimit := fs.Int("detail-limit", 0, "max characters to render in PostgreSQL message details (0 = unlimited)")
	captureBytes := fs.Uint("capture-bytes", wire.DefaultCaptureBytes, "effective plaintext byte limit per traced PostgreSQL read/write call (max 4096)")
	waitForPostgres := fs.Bool("wait-for-postgres", false, "keep running and attach when PostgreSQL processes appear")
	scanInterval := fs.Duration("scan-interval", wire.DefaultScanInterval, "how often to rescan for PostgreSQL executables when waiting")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSessionUsage(os.Stdout)
			return nil
		}
		return fmt.Errorf("parse session flags: %w", err)
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

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	netRuntime, err := bpf.Open(uint16(*port))
	if err != nil {
		return fmt.Errorf("failed to start BPF runtime: %v\nrun as root or with the capabilities required to load tracing/kprobe eBPF programs", err)
	}
	defer func() { _ = netRuntime.Close() }()

	wireRuntime, err := wire.Open(wire.Options{
		CaptureBytes:    uint32(*captureBytes),
		WaitForPostgres: *waitForPostgres,
		ScanInterval:    *scanInterval,
	})
	if err != nil {
		return fmt.Errorf("failed to start %s runtime: %w", branding.WireCommandName, err)
	}
	defer func() { _ = wireRuntime.Close() }()

	coll := collector.New(netRuntime)
	coll.Start(ctx)

	parser := wire.NewParser(*detailLimit)
	corr := correlator.New()
	history := newSessionEventHistory(*recent)
	wireErrCh := make(chan error, 1)
	go func() {
		wireErrCh <- wireRuntime.RunEventLoop(ctx, func(chunk wire.Chunk) {
			for _, event := range parser.Feed(chunk) {
				corr.Handle(event)
			}
		})
	}()

	render := func(clear bool) error {
		networkSnapshot, err := coll.Snapshot()
		if err != nil {
			return err
		}
		snapshot := corr.BuildSnapshot(uint16(*port), networkSnapshot, wireRuntime.AttachMode(), wireRuntime.Executables(), *recent)
		snapshot = correlator.FilterSnapshot(snapshot, query)
		if format == outputText {
			snapshot.Recent = history.Merge(snapshot.Recent)
			if clear {
				fmt.Print("\x1b[H\x1b[2J")
			}
			cli.RenderSessionSnapshot(os.Stdout, snapshot)
			return nil
		}
		return cli.RenderSessionSnapshotJSON(os.Stdout, snapshot)
	}

	if err := render(false); err != nil {
		return err
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if format == outputText {
				fmt.Println()
			}
			return nil
		case err := <-wireErrCh:
			if err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			if err := render(!*noClear && format == outputText); err != nil {
				return err
			}
		}
	}
}

func printSessionUsage(w io.Writer) {
	fmt.Fprintf(w, "  %s %s session [-port 5432] [-interval 2s] [-no-clear] [-output text|json] [-client FILTER] [-server FILTER] [-pid PID] [-netns NS] [-cgroup ID] [-limit N] [-sort rate|tx|rx|age|retransmits] [-recent N] [-detail-limit N] [-capture-bytes N] [-wait-for-postgres] [-scan-interval DURATION]\n", branding.ExecutableName, branding.MonitorCommandName)
	fmt.Fprintf(w, "    combines %s %s connection counters with %s %s content groups: queries/sql, connection configuration, and WAL transmission\n", branding.ExecutableName, branding.MonitorCommandName, branding.ExecutableName, branding.WireCommandName)
}
