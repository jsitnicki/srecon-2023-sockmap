#!/bin/bash

if ! findmnt /sys/fs/bpf > /dev/null; then
  mount -t bpf none /sys/fs/bpf
fi

bpftool prog loadall \
        policy_egress.bpf.o \
        /sys/fs/bpf \
        pinmaps /sys/fs/bpf

bpftool prog attach \
        pinned /sys/fs/bpf/sk_msg_prog \
        sk_msg_verdict \
        pinned /sys/fs/bpf/sock_map

if [ ! -d /sys/fs/cgroup/unified/test.slice ]; then
  mkdir /sys/fs/cgroup/unified/test.slice
fi

bpftool cgroup attach \
        /sys/fs/cgroup/unified/test.slice \
        cgroup_sock_ops \
        pinned /sys/fs/bpf/sockops_prog

ip addr add 192.0.2.1/24 dev lo
ip link set dev lo up

echo $$ > /sys/fs/cgroup/unified/test.slice/cgroup.procs

nc -lke /bin/true 1234 &
sleep 0.5

echo -n a | strace -e sendto nc 127.0.0.1 1234   # expect OK
echo -n b | strace -e sendto nc 192.0.2.1 1234   # expect EACCES

