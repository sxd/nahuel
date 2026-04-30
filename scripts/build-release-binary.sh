#!/usr/bin/env bash
# Copyright 2026 Jonathan Gonzalez V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <amd64|arm64> <output-path>" >&2
  exit 2
fi

arch="$1"
output="$2"

case "${arch}" in
  amd64|arm64)
    ;;
  *)
    echo "unsupported architecture: ${arch}" >&2
    exit 2
    ;;
esac

host_arch="$(uname -m)"
case "${host_arch}" in
  x86_64)
    host_arch="amd64"
    ;;
  aarch64|arm64)
    host_arch="arm64"
    ;;
esac

if [[ "${host_arch}" != "${arch}" ]]; then
  echo "native build required: host architecture ${host_arch} cannot generate BPF objects for ${arch}" >&2
  exit 2
fi

if ! command -v go >/dev/null 2>&1 && [[ -x /usr/local/go/bin/go ]]; then
  export PATH="/usr/local/go/bin:${PATH}"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go toolchain not found on PATH" >&2
  exit 2
fi

export BPF2GO_TARGET_ARCH="${arch}"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
go generate ./internal/bpf
go generate ./internal/wire

mkdir -p "$(dirname "${output}")"
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags='-s -w' -o "${output}" ./cmd/nahuel
