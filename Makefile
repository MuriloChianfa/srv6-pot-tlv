SRC_DIR := ebpf
LIB_DIR := lib
BUILD_DIR := build

EBPF_TARGETS := endt6 endx

CLANG := clang
CLANG_FLAGS := -O2 -g -Wextra -target bpf -I$(SRC_DIR)/$(LIB_DIR) -I/usr/include/

$(shell mkdir -p $(BUILD_DIR))

all: $(EBPF_TARGETS)

$(EBPF_TARGETS):
	$(CLANG) $(CLANG_FLAGS) -c $(SRC_DIR)/$@.c -o $(BUILD_DIR)/$@.o

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean $(EBPF_TARGETS)
