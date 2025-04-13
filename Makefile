SRC_DIR := ebpf
INCLUDE_DIR := include
BUILD_DIR := build

EBPF_TARGETS := seg6_pot_tlv

CLANG := clang
CLANG_FLAGS := -O2 -Wextra -target bpf -I$(SRC_DIR)/$(INCLUDE_DIR) -I/usr/include/

$(shell mkdir -p $(BUILD_DIR))

all: $(EBPF_TARGETS)

$(EBPF_TARGETS):
	$(CLANG) $(CLANG_FLAGS) -c $(SRC_DIR)/$@.c -o $(BUILD_DIR)/$@.o

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean $(EBPF_TARGETS)
