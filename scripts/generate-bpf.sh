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

arch="${BPF2GO_TARGET_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64)
    bpf_arch="x86"
    ;;
  aarch64|arm64)
    bpf_arch="arm64"
    ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

name="${1:-netmon}"
source="${2:-../../bpf/netmon.bpf.c}"

prepend_go_header() {
  local file="$1"
  local tmp

  if [[ ! -f "$file" ]]; then
    return
  fi

  tmp="$(mktemp)"
  cat > "$tmp" <<'HEADER'
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

HEADER
  cat "$file" >> "$tmp"
  mv "$tmp" "$file"
}

go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -Wall -D__TARGET_ARCH_${bpf_arch}" \
  "$name" "$source" -- -I../../bpf

prepend_go_header "${name}_bpfel.go"
prepend_go_header "${name}_bpfeb.go"
