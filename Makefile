# bpf/Makefile

BPF_CFLAGS := -O2 -g \
  -target bpf \
  -Wextra \
  -I./ebpf/ -I/usr/include/

BPF_SRCS := ebpf/seg6_blake3_pot_tlv.c
BPF_OBJS := ebpf/seg6_blake3_pot_tlv.o
BPF_IF   := enp2s0
TARGET   := seg6_blake3_pot_tlvy

.PHONY: cmd

all: cmd $(BPF_OBJS)

%.o: %.c
	clang $(BPF_CFLAGS) -c $< -o $@

cmd:
	#go build -C cmd -o ../$(TARGET)

clean:
	rm -f $(BPF_OBJS)
	rm -f $(TARGET)

show:
	sudo bpftool prog show
	sudo bpftool map list

logs:
	echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
	sudo cat /sys/kernel/debug/tracing/trace_pipe
