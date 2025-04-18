BASEDIR = .
OUTPUT = libbpfgo/output/

LIBBPF_OBJ = $(OUTPUT)/libbpf/libbpf.a
LIBBPF_INCLUDE_DIR = $(OUTPUT)

SRC_DIR := ebpf
INCLUDE_DIR := include
BUILD_DIR := cmd/build

EBPF_TARGETS := seg6_pot_tlv

CLANG := clang
CLANG_FLAGS := -O2 -g -Wextra -target bpf -I$(SRC_DIR)/$(INCLUDE_DIR) -I$(LIBBPF_INCLUDE_DIR) -I/usr/include

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g')
CLANG_FLAGS += -D__TARGET_ARCH_$(ARCH)

ABS_BUILD_DIR := $(shell pwd)/$(BUILD_DIR)

OUTPUT_BIN := seg6-pot-tlv

CGO_ENABLED = 1
CGO_CFLAGS := -I$(PWD)/libbpfgo/libbpf/include/uapi
CGO_LDFLAGS := -L$(PWD)/libbpfgo/output/libbpf -l:libbpf.a -lelf -lzstd -pthread -lz
CGO_EXTLDFLAGS = '-w -extldflags "-static"'

$(shell mkdir -p $(shell pwd)/$(BUILD_DIR))

all: $(OUTPUT_BIN)-static

$(BUILD_DIR)/$(EBPF_TARGETS).o: $(SRC_DIR)/$(EBPF_TARGETS).bpf.c $(wildcard $(SRC_DIR)/$(INCLUDE_DIR)/*/*.h) $(wildcard $(SRC_DIR)/$(INCLUDE_DIR)/*.h)
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

prepare-libbpf-static:
	@echo "Building static libbpf dependency in $(BASEDIR)..."
	git clone git@github.com:aquasecurity/libbpfgo.git; echo "libbpfgo updated"
	cd libbpfgo && make libbpfgo-static
	rm -rf output

$(OUTPUT_BIN)-static: $(BUILD_DIR)/$(EBPF_TARGETS).o prepare-libbpf-static
	@echo "Building Go application statically..."
	cd cmd && CGO_ENABLED=$(CGO_ENABLED) \
		CGO_CFLAGS=$(CGO_CFLAGS) \
		CGO_LDFLAGS="-L$(PWD)/libbpfgo/output/libbpf -l:libbpf.a -lelf -lzstd -pthread -lz" \
		GOOS=linux GOARCH=$(ARCH) \
		go build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS) \
		-o build/$(OUTPUT_BIN) .

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) libbpfgo $(OUTPUT_BIN)-static

.PHONY: all clean prepare-libbpf-static $(OUTPUT_BIN)-static