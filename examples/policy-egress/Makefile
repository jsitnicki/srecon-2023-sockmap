BPFTOOL ?= bpftool
CC_BPF ?= clang
CFLAGS_BPF ?= -Wall -Wextra -Werror -ggdb

%.bpf.o: %.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -O2 -target bpf -c -o $@ $<

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean

all: policy_egress.bpf.o

clean:
	rm -f *.bpf.o *.skel.h
