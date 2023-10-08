CC_BPF ?= clang
CFLAGS_BPF ?= -Wall -Wextra -Werror -ggdb

%.bpf.o: %.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -O2 -target bpf -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean

all: redir_bypass.bpf.o

clean:
	rm -f *.bpf.o

vm:
	virtme-run --installed-kernel --pwd --memory 2G --cpus 2
