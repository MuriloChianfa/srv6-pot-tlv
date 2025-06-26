BASEDIR = .
OUTPUT = libbpfgo/output/

LIBBPF_OBJ = $(OUTPUT)/libbpf/libbpf.a
LIBBPF_INCLUDE_DIR = $(OUTPUT)

SRC_DIR := bpf
INCLUDE_DIR := $(SRC_DIR)
BUILD_DIR := cmd/build

EBPF_SOURCE := seg6-pot-tlv.bpf.c

ALGORITHMS := POLY1305 SIPHASH BLAKE3 HALFSIPHASH HMAC_SHA256
ALGO_FLAGS := $(foreach algo,$(ALGORITHMS),-D$(algo))
ALGO_NAMES := $(foreach algo,$(ALGORITHMS),$(shell echo $(algo) | tr '[:upper:]' '[:lower:]'))

DEFAULT_ALGO_FLAG := -DBLAKE3
DEFAULT_ALGO_NAME := blake3

CLANG := clang
BASE_CLANG_FLAGS := -O2 -g -Wall -Wextra -Wconversion -Werror -target bpf
BASE_CLANG_FLAGS += -mllvm -bpf-stack-size=2048
BASE_CLANG_FLAGS += -I$(SRC_DIR) \
	-I$(LIBBPF_INCLUDE_DIR) -I/usr/include

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g')
BASE_CLANG_FLAGS += -D__TARGET_ARCH_$(ARCH)

ABS_BUILD_DIR := $(shell pwd)/$(BUILD_DIR)

OUTPUT_BIN_PREFIX := seg6-pot-tlv
CGO_ENABLED = 1
CGO_CFLAGS := -I$(PWD)/libbpfgo/libbpf/include/uapi
CGO_LDFLAGS := -L$(PWD)/libbpfgo/output/libbpf -l:libbpf.a -lelf -lzstd -pthread -lz
CGO_EXTLDFLAGS = '-w -extldflags "-static"'
GO_BUILD_CMD = go build -tags netgo -ldflags $(CGO_EXTLDFLAGS)

$(shell mkdir -p $(BUILD_DIR))

all: reset $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-blake3 $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-poly1305 $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-siphash $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-halfsiphash $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-hmac-sha256 tmpclean

$(LIBBPF_OBJ):
	@if [ ! -d "libbpfgo" ]; then \
		git clone https://github.com/aquasecurity/libbpfgo.git; \
	else \
		echo "libbpfgo directory already exists, skipping clone."; \
	fi
	cd libbpfgo && make libbpfgo-static

$(BUILD_DIR)/seg6_pot_tlv_%.o: $(EBPF_SOURCE) $(wildcard $(SRC_DIR)/*/*.h) $(wildcard $(SRC_DIR)/*.h) $(LIBBPF_OBJ)
	$(CLANG) $(BASE_CLANG_FLAGS) $(ALGO_FLAG) -c $< -o $@

$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-%: $(BUILD_DIR)/seg6_pot_tlv_%.o $(LIBBPF_OBJ)
	@cp $(BUILD_DIR)/seg6_pot_tlv_$(ALGO_NAME).o $(BUILD_DIR)/seg6_pot_tlv.o
	@echo "$(GO_BUILD_CMD) -o $(ABS_BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-$(ALGO_NAME) ."
	@cd cmd && CGO_ENABLED=$(CGO_ENABLED) \
		CGO_CFLAGS=$(CGO_CFLAGS) \
		CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO_BUILD_CMD) -o $(ABS_BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-$(ALGO_NAME) .

default_name: reset $(BUILD_DIR)/seg6_pot_tlv_blake3.o $(LIBBPF_OBJ)
	@cp $(BUILD_DIR)/seg6_pot_tlv_blake3.o $(BUILD_DIR)/seg6_pot_tlv.o
	@echo "$(GO_BUILD_CMD) -o $(ABS_BUILD_DIR)/$(OUTPUT_BIN_PREFIX) ."
	@cd cmd && CGO_ENABLED=$(CGO_ENABLED) \
		CGO_CFLAGS=$(CGO_CFLAGS) \
		CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO_BUILD_CMD) -o $(ABS_BUILD_DIR)/$(OUTPUT_BIN_PREFIX) .
$(BUILD_DIR)/seg6_pot_tlv_blake3.o: ALGO_FLAG = -DBLAKE3


poly1305: $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-poly1305
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-poly1305: ALGO_FLAG = -DPOLY1305
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-poly1305: ALGO_NAME = poly1305
$(BUILD_DIR)/seg6_pot_tlv_poly1305.o: ALGO_FLAG = -DPOLY1305

siphash: $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-siphash
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-siphash: ALGO_FLAG = -DSIPHASH
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-siphash: ALGO_NAME = siphash
$(BUILD_DIR)/seg6_pot_tlv_siphash.o: ALGO_FLAG = -DSIPHASH

blake3: $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-blake3
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-blake3: ALGO_FLAG = -DBLAKE3
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-blake3: ALGO_NAME = blake3
$(BUILD_DIR)/seg6_pot_tlv_blake3.o: ALGO_FLAG = -DBLAKE3

halfsiphash: $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-halfsiphash
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-halfsiphash: ALGO_FLAG = -DHALFSIPHASH
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-halfsiphash: ALGO_NAME = halfsiphash
$(BUILD_DIR)/seg6_pot_tlv_halfsiphash.o: ALGO_FLAG = -DHALFSIPHASH

hmac-sha256: $(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-hmac-sha256
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-hmac-sha256: ALGO_FLAG = -DHMAC_SHA256
$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-hmac-sha256: ALGO_NAME = hmac-sha256
$(BUILD_DIR)/seg6_pot_tlv_hmac-sha256.o: ALGO_FLAG = -DHMAC_SHA256

all_algorithms: $(foreach algo,$(ALGO_NAMES),$(BUILD_DIR)/$(OUTPUT_BIN_PREFIX)-$(algo))

reset:
	@rm -rf $(BUILD_DIR)
	@cd cmd && mkdir build

clean:
	rm -rf $(BUILD_DIR)
	rm -rf libbpfgo

distclean: clean
	rm -rf libbpfgo

tmpclean:
	@rm -rf $(BUILD_DIR)/seg6_pot_tlv.o

.DEFAULT_GOAL := default_name
.PHONY: all all_algorithms clean distclean poly1305 siphash blake3 halfsiphash hmac-sha256 default_name