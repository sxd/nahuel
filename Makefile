BPFTOOL ?= bpftool
VMLINUX ?= /sys/kernel/btf/vmlinux
BIN_DIR := bin
TARGET := $(BIN_DIR)/nahuel

.PHONY: all generate build test vet verify release-binary clean

all: build

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@

generate: bpf/vmlinux.h
	go generate ./internal/bpf
	go generate ./internal/wire

build: generate
	mkdir -p $(BIN_DIR)
	go build -o $(TARGET) ./cmd/nahuel

test:
	go test ./...

vet:
	go vet ./...

verify: generate
	go build ./...
	go test ./...
	go vet ./...

release-binary:
	@if [ -z "$(ARCH)" ] || [ -z "$(OUTPUT)" ]; then echo "usage: make release-binary ARCH=<amd64|arm64> OUTPUT=<path>"; exit 2; fi
	./scripts/build-release-binary.sh "$(ARCH)" "$(OUTPUT)"

clean:
	rm -rf $(BIN_DIR)
	rm -f internal/bpf/netmon_bpfel.go internal/bpf/netmon_bpfeb.go
	rm -f internal/bpf/netmon_bpfel.o internal/bpf/netmon_bpfeb.o
	rm -f internal/wire/wire_bpfel.go internal/wire/wire_bpfeb.go
	rm -f internal/wire/wire_bpfel.o internal/wire/wire_bpfeb.o
