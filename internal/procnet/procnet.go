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

package procnet

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Connection struct {
	PID        uint32
	Netns      uint32
	ClientAddr string
	ClientPort uint16
	ServerAddr string
	ServerPort uint16
}

func FindTCPConnections(pid uint32, serverPort uint16) ([]Connection, error) {
	inodeSet, err := socketInodes(pid)
	if err != nil {
		return nil, err
	}
	if len(inodeSet) == 0 {
		return nil, nil
	}

	netns, _ := netnsInode(pid)
	paths := []struct {
		path string
		ipv6 bool
	}{
		{path: fmt.Sprintf("/proc/%d/net/tcp", pid), ipv6: false},
		{path: fmt.Sprintf("/proc/%d/net/tcp6", pid), ipv6: true},
	}

	var out []Connection
	for _, item := range paths {
		conns, err := parseTCPFile(item.path, pid, netns, inodeSet, serverPort, item.ipv6)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		out = append(out, conns...)
	}
	return out, nil
}

func socketInodes(pid uint32) (map[string]struct{}, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		inode, ok := parseSocketInode(target)
		if ok {
			out[inode] = struct{}{}
		}
	}
	return out, nil
}

func parseSocketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), true
}

func netnsInode(pid uint32) (uint32, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return 0, err
	}
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start < 0 || end <= start+1 {
		return 0, fmt.Errorf("unexpected netns link %q", target)
	}
	value, err := strconv.ParseUint(target[start+1:end], 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func parseTCPFile(path string, pid uint32, netns uint32, inodeSet map[string]struct{}, serverPort uint16, ipv6 bool) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Connection
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		inode := fields[9]
		if _, ok := inodeSet[inode]; !ok {
			continue
		}
		localAddr, localPort, err := parseProcAddr(fields[1], ipv6)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseProcAddr(fields[2], ipv6)
		if err != nil {
			continue
		}
		if localPort != serverPort && remotePort != serverPort {
			continue
		}
		conn := Connection{PID: pid, Netns: netns}
		if localPort == serverPort {
			conn.ServerAddr = localAddr
			conn.ServerPort = localPort
			conn.ClientAddr = remoteAddr
			conn.ClientPort = remotePort
		} else {
			conn.ServerAddr = remoteAddr
			conn.ServerPort = remotePort
			conn.ClientAddr = localAddr
			conn.ClientPort = localPort
		}
		out = append(out, conn)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseProcAddr(value string, ipv6 bool) (string, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address %q", value)
	}
	portValue, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	ip, err := decodeHexIP(parts[0], ipv6)
	if err != nil {
		return "", 0, err
	}
	return ip.String(), uint16(portValue), nil
}

func decodeHexIP(raw string, ipv6 bool) (net.IP, error) {
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if !ipv6 {
		if len(decoded) != 4 {
			return nil, fmt.Errorf("unexpected ipv4 hex len %d", len(decoded))
		}
		return net.IPv4(decoded[3], decoded[2], decoded[1], decoded[0]), nil
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("unexpected ipv6 hex len %d", len(decoded))
	}
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		chunk := decoded[i*4 : (i+1)*4]
		ip[i*4+0] = chunk[3]
		ip[i*4+1] = chunk[2]
		ip[i*4+2] = chunk[1]
		ip[i*4+3] = chunk[0]
	}
	return ip, nil
}
