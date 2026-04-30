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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	attachModeSecure = "uprobe:secure"
	attachModeBeTLS  = "uprobe:be_tls"
	attachModeMixed  = "uprobe:mixed"
	attachModeNone   = "uprobe:none"

	directionClientToServer = 1
	directionServerToClient = 2

	apiSecureRead  = 1
	apiSecureWrite = 2
	apiBeTLSRead   = 3
	apiBeTLSWrite  = 4

	DefaultCaptureBytes = 4096
	MaxCaptureBytes     = 4096
	DefaultScanInterval = 15 * time.Second
)

var ErrNoPostgresExecutables = errors.New("no postgres executable found in /proc or standard install paths")

type Options struct {
	CaptureBytes    uint32
	WaitForPostgres bool
	ScanInterval    time.Duration
}

type Direction uint8

const (
	DirectionUnknown        Direction = 0
	DirectionClientToServer Direction = directionClientToServer
	DirectionServerToClient Direction = directionServerToClient
)

func (d Direction) String() string {
	switch d {
	case DirectionClientToServer:
		return "client->server"
	case DirectionServerToClient:
		return "server->client"
	default:
		return "unknown"
	}
}

type API uint8

const (
	APIUnknown     API = 0
	APISecureRead  API = apiSecureRead
	APISecureWrite API = apiSecureWrite
	APIBeTLSRead   API = apiBeTLSRead
	APIBeTLSWrite  API = apiBeTLSWrite
)

func (a API) String() string {
	switch a {
	case APISecureRead:
		return "secure_read"
	case APISecureWrite:
		return "secure_write"
	case APIBeTLSRead:
		return "be_tls_read"
	case APIBeTLSWrite:
		return "be_tls_write"
	default:
		return "unknown"
	}
}

type Chunk struct {
	TimestampNs uint64
	ConnPtr     uint64
	CgroupID    uint64
	PID         uint32
	TID         uint32
	TotalLen    uint32
	CapturedLen uint32
	Direction   Direction
	API         API
	Truncated   bool
	Comm        string
	Data        []byte
}

type chunkRecord struct {
	TimestampNs uint64
	ConnPtr     uint64
	CgroupID    uint64
	PID         uint32
	TID         uint32
	TotalLen    uint32
	CapturedLen uint32
	Direction   uint8
	API         uint8
	Truncated   uint8
	Pad         uint8
	Comm        [16]byte
	Data        [4097]byte
}

type runtimeMaps struct {
	WireEvents   *ebpf.Map `ebpf:"wire_events"`
	WireInflight *ebpf.Map `ebpf:"wire_inflight"`
}

type runtimeObjects struct {
	runtimeMaps
	TrackSecureReadEnter  *ebpf.Program `ebpf:"track_secure_read_enter"`
	TrackSecureReadExit   *ebpf.Program `ebpf:"track_secure_read_exit"`
	TrackSecureWriteEnter *ebpf.Program `ebpf:"track_secure_write_enter"`
	TrackSecureWriteExit  *ebpf.Program `ebpf:"track_secure_write_exit"`
	TrackBeTlsReadEnter   *ebpf.Program `ebpf:"track_be_tls_read_enter"`
	TrackBeTlsReadExit    *ebpf.Program `ebpf:"track_be_tls_read_exit"`
	TrackBeTlsWriteEnter  *ebpf.Program `ebpf:"track_be_tls_write_enter"`
	TrackBeTlsWriteExit   *ebpf.Program `ebpf:"track_be_tls_write_exit"`
}

func (o *runtimeObjects) Close() error {
	return closeAll(
		o.TrackSecureReadEnter,
		o.TrackSecureReadExit,
		o.TrackSecureWriteEnter,
		o.TrackSecureWriteExit,
		o.TrackBeTlsReadEnter,
		o.TrackBeTlsReadExit,
		o.TrackBeTlsWriteEnter,
		o.TrackBeTlsWriteExit,
		o.WireEvents,
		o.WireInflight,
	)
}

type executableTarget struct {
	Key  string
	Path string
}

type attachedExecutable struct {
	mode  string
	path  string
	links []link.Link
}

type Runtime struct {
	reader          *ringbuf.Reader
	closer          io.Closer
	objects         *runtimeObjects
	captureBytes    uint32
	waitForPostgres bool
	scanInterval    time.Duration

	mu         sync.RWMutex
	attached   map[string]attachedExecutable
	attachMode string
}

var (
	memlockOnce sync.Once
	memlockErr  error
)

func Open(opts Options) (*Runtime, error) {
	if opts.CaptureBytes == 0 {
		opts.CaptureBytes = DefaultCaptureBytes
	}
	if opts.CaptureBytes > MaxCaptureBytes {
		return nil, fmt.Errorf("capture bytes %d exceeds max %d", opts.CaptureBytes, MaxCaptureBytes)
	}
	if opts.ScanInterval <= 0 {
		opts.ScanInterval = DefaultScanInterval
	}

	memlockOnce.Do(func() {
		memlockErr = rlimit.RemoveMemlock()
	})
	if memlockErr != nil && !errors.Is(memlockErr, unix.EPERM) {
		return nil, fmt.Errorf("remove memlock rlimit: %w", memlockErr)
	}

	spec, err := loadWire()
	if err != nil {
		return nil, fmt.Errorf("load wire BPF spec: %w", err)
	}

	var objs runtimeObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load wire BPF objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.WireEvents)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("open wire ring buffer: %w", err)
	}

	rt := &Runtime{
		reader:          reader,
		closer:          &objs,
		objects:         &objs,
		captureBytes:    opts.CaptureBytes,
		waitForPostgres: opts.WaitForPostgres,
		scanInterval:    opts.ScanInterval,
		attached:        make(map[string]attachedExecutable),
		attachMode:      attachModeNone,
	}

	if err := rt.refreshAttachments(); err != nil {
		if !errors.Is(err, ErrNoPostgresExecutables) || !opts.WaitForPostgres {
			rt.Close()
			return nil, err
		}
	}

	return rt, nil
}

func (rt *Runtime) AttachMode() string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.attachMode
}

func (rt *Runtime) Executables() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	out := make([]string, 0, len(rt.attached))
	for _, attached := range rt.attached {
		out = append(out, attached.path)
	}
	sort.Strings(out)
	return out
}

func (rt *Runtime) RunEventLoop(ctx context.Context, handle func(Chunk)) error {
	if rt.waitForPostgres {
		go rt.runAttachLoop(ctx)
	}

	for {
		record, err := rt.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read wire ring buffer: %w", err)
		}

		var raw chunkRecord
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return fmt.Errorf("decode wire chunk: %w", err)
		}

		captured := int(raw.CapturedLen)
		if captured > len(raw.Data) {
			captured = len(raw.Data)
		}
		if rt.captureBytes > 0 && captured > int(rt.captureBytes) {
			captured = int(rt.captureBytes)
		}
		truncated := raw.Truncated != 0 || int(raw.CapturedLen) > captured

		handle(Chunk{
			TimestampNs: raw.TimestampNs,
			ConnPtr:     raw.ConnPtr,
			CgroupID:    raw.CgroupID,
			PID:         raw.PID,
			TID:         raw.TID,
			TotalLen:    raw.TotalLen,
			CapturedLen: uint32(captured),
			Direction:   Direction(raw.Direction),
			API:         API(raw.API),
			Truncated:   truncated,
			Comm:        commString(raw.Comm),
			Data:        append([]byte(nil), raw.Data[:captured]...),
		})
	}
}

func (rt *Runtime) Close() error {
	if rt.reader != nil {
		_ = rt.reader.Close()
	}

	rt.mu.Lock()
	for _, attached := range rt.attached {
		closeLinks(attached.links)
	}
	rt.attached = map[string]attachedExecutable{}
	rt.mu.Unlock()

	if rt.closer != nil {
		return rt.closer.Close()
	}
	return nil
}

func (rt *Runtime) runAttachLoop(ctx context.Context) {
	ticker := time.NewTicker(rt.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = rt.refreshAttachments()
		}
	}
}

func (rt *Runtime) refreshAttachments() error {
	targets := discoverExecutableTargets()
	if len(targets) == 0 {
		rt.mu.RLock()
		hasAttached := len(rt.attached) > 0
		rt.mu.RUnlock()
		if hasAttached {
			return nil
		}
		return ErrNoPostgresExecutables
	}

	var errs []string
	for _, target := range targets {
		rt.mu.RLock()
		_, exists := rt.attached[target.Key]
		rt.mu.RUnlock()
		if exists {
			continue
		}

		mode, links, err := attachExecutable(target.Path, rt.objects)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		rt.mu.Lock()
		rt.attached[target.Key] = attachedExecutable{
			mode:  mode,
			path:  target.Path,
			links: links,
		}
		rt.recomputeAttachModeLocked()
		rt.mu.Unlock()
	}

	rt.mu.RLock()
	hasAttached := len(rt.attached) > 0
	rt.mu.RUnlock()
	if hasAttached {
		return nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("attach postgres uprobes: %s", strings.Join(errs, "; "))
	}
	return ErrNoPostgresExecutables
}

func (rt *Runtime) recomputeAttachModeLocked() {
	secure := false
	beTLS := false
	for _, attached := range rt.attached {
		switch attached.mode {
		case attachModeSecure:
			secure = true
		case attachModeBeTLS:
			beTLS = true
		}
	}

	switch {
	case secure && !beTLS:
		rt.attachMode = attachModeSecure
	case !secure && beTLS:
		rt.attachMode = attachModeBeTLS
	case secure && beTLS:
		rt.attachMode = attachModeMixed
	default:
		rt.attachMode = attachModeNone
	}
}

func attachExecutable(path string, objs *runtimeObjects) (string, []link.Link, error) {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return "", nil, fmt.Errorf("%s: open executable: %w", path, err)
	}

	if links, err := attachSecure(ex, objs); err == nil {
		return attachModeSecure, links, nil
	}

	links, err := attachBeTLS(ex, objs)
	if err != nil {
		return "", nil, fmt.Errorf("%s: secure and be_tls symbol attach failed: %w", path, err)
	}
	return attachModeBeTLS, links, nil
}

func attachSecure(ex *link.Executable, objs *runtimeObjects) ([]link.Link, error) {
	return attachSymbolSet(
		ex,
		"secure_read",
		objs.TrackSecureReadEnter,
		objs.TrackSecureReadExit,
		"secure_write",
		objs.TrackSecureWriteEnter,
		objs.TrackSecureWriteExit,
	)
}

func attachBeTLS(ex *link.Executable, objs *runtimeObjects) ([]link.Link, error) {
	return attachSymbolSet(
		ex,
		"be_tls_read",
		objs.TrackBeTlsReadEnter,
		objs.TrackBeTlsReadExit,
		"be_tls_write",
		objs.TrackBeTlsWriteEnter,
		objs.TrackBeTlsWriteExit,
	)
}

func attachSymbolSet(ex *link.Executable, readSym string, readEnter *ebpf.Program, readExit *ebpf.Program, writeSym string, writeEnter *ebpf.Program, writeExit *ebpf.Program) ([]link.Link, error) {
	links := make([]link.Link, 0, 4)

	cleanup := func(err error) ([]link.Link, error) {
		closeLinks(links)
		return nil, err
	}

	l, err := ex.Uprobe(readSym, readEnter, nil)
	if err != nil {
		return cleanup(err)
	}
	links = append(links, l)

	l, err = ex.Uretprobe(readSym, readExit, nil)
	if err != nil {
		return cleanup(err)
	}
	links = append(links, l)

	l, err = ex.Uprobe(writeSym, writeEnter, nil)
	if err != nil {
		return cleanup(err)
	}
	links = append(links, l)

	l, err = ex.Uretprobe(writeSym, writeExit, nil)
	if err != nil {
		return cleanup(err)
	}
	links = append(links, l)

	return links, nil
}

func discoverExecutableTargets() []executableTarget {
	targetsByInode := make(map[string]executableTarget)
	add := func(path string, prefer bool) {
		if path == "" {
			return
		}

		candidate := strings.TrimSuffix(path, " (deleted)")
		if !strings.HasPrefix(candidate, "/proc/") {
			resolved, err := filepath.EvalSymlinks(candidate)
			if err == nil {
				candidate = resolved
			}
		}

		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			return
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		key := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		existing, exists := targetsByInode[key]
		if exists {
			if strings.HasPrefix(existing.Path, "/proc/") || !prefer {
				return
			}
		}
		targetsByInode[key] = executableTarget{
			Key:  key,
			Path: candidate,
		}
	}

	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}

			exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
			if err != nil {
				continue
			}
			base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
			if base != "postgres" && base != "postmaster" {
				continue
			}
			add(filepath.Join("/proc", entry.Name(), "exe"), true)
		}
	}

	for _, pattern := range []string{
		"/usr/lib/postgresql/*/bin/postgres",
		"/usr/local/pgsql/bin/postgres",
		"/usr/bin/postgres",
		"/usr/sbin/postgres",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			add(match, false)
		}
	}

	out := make([]executableTarget, 0, len(targetsByInode))
	for _, target := range targetsByInode {
		out = append(out, target)
	}
	sort.Slice(out, func(i int, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

func commString(raw [16]byte) string {
	return strings.TrimRight(string(raw[:]), "\x00")
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func closeAll(closers ...io.Closer) error {
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
