BASEDIR = .
OUTPUT = libbpfgo/output/

LIBBPF_OBJ = $(OUTPUT)/libbpf/libbpf.a
LIBBPF_INCLUDE_DIR = $(OUTPUT)

SRC_DIR := ebpf
INCLUDE_DIR := $(SRC_DIR)
BUILD_DIR := cmd/build

EBPF_TARGETS := seg6_pot_tlv

CLANG := clang
CLANG_FLAGS := -O2 -g -Wall -Wextra -Wconversion -target bpf
CLANG_FLAGS += -mllvm -bpf-stack-size=2048
CLANG_FLAGS += -I$(SRC_DIR) \
	-I$(LIBBPF_INCLUDE_DIR) -I/usr/include

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g')
CLANG_FLAGS += -D__TARGET_ARCH_$(ARCH)

ABS_BUILD_DIR := $(shell pwd)/$(BUILD_DIR)

OUTPUT_BIN := seg6-pot-tlv

CGO_ENABLED = 1
CGO_CFLAGS := -I$(PWD)/libbpfgo/libbpf/include/uapi
CGO_LDFLAGS := -L$(PWD)/libbpfgo/output/libbpf -l:libbpf.a -lelf -lzstd -pthread -lz
CGO_EXTLDFLAGS = '-w -extldflags "-static"'
CGO_BUILD := go build -tags netgo -ldflags $(CGO_EXTLDFLAGS) -o build/$(OUTPUT_BIN) .

$(shell mkdir -p $(shell pwd)/$(BUILD_DIR))

all: $(BUILD_DIR)/$(OUTPUT_BIN)

$(BUILD_DIR)/$(EBPF_TARGETS).o: $(SRC_DIR)/ebpf.c $(wildcard $(SRC_DIR)/*/*.h) $(wildcard $(SRC_DIR)/*.h)
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(LIBBPF_OBJ):
	git clone git@github.com:aquasecurity/libbpfgo.git 2>/dev/null; echo "libbpfgo updated"
	cd libbpfgo && make libbpfgo-static
	rm -rf output

$(BUILD_DIR)/$(OUTPUT_BIN): $(BUILD_DIR)/$(EBPF_TARGETS).o $(LIBBPF_OBJ)
	@cd cmd && CGO_ENABLED=$(CGO_ENABLED) \
		CGO_CFLAGS=$(CGO_CFLAGS) \
		CGO_LDFLAGS="-L$(PWD)/libbpfgo/output/libbpf -l:libbpf.a -lelf -lzstd -pthread -lz" \
		GOOS=linux GOARCH=$(ARCH) \
		$(CGO_BUILD)
	@echo "$(CGO_BUILD)"

clean:
	rm -rf $(BUILD_DIR) libbpfgo $(OUTPUT_BIN)

.PHONY: all clean