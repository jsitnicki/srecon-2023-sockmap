#!/bin/bash

set -o errexit
set -o nounset

# Setup

sysctl -w kernel.bpf_stats_enabled=1

if ! findmnt /sys/fs/bpf > /dev/null; then
  mount -t bpf none /sys/fs/bpf
fi

mkdir -p /sys/fs/bpf/test

bpftool prog loadall \
        redir_bypass.bpf.o \
        /sys/fs/bpf/test \
        pinmaps /sys/fs/bpf/test

bpftool prog attach \
        pinned /sys/fs/bpf/test/sk_msg_prog \
        sk_msg_verdict \
        pinned /sys/fs/bpf/test/sock_map

if [ ! -d /sys/fs/cgroup/unified/test.slice ]; then
  mkdir /sys/fs/cgroup/unified/test.slice
fi

ip netns add A
ip netns add B

ip -n A link add name veth0 type veth peer name veth0 netns B

ip -n A link set dev lo up
ip -n B link set dev lo up

ip -n A link set dev veth0 up
ip -n B link set dev veth0 up

ip -n A addr add 10.0.0.1/24 dev veth0
ip -n B addr add 10.0.0.2/24 dev veth0

ip -n A link show veth0
ip -n B link show veth0

echo $$ > /sys/fs/cgroup/unified/test.slice/cgroup.procs

ip netns exec A \
   sockperf server -i 10.0.0.1 --tcp --daemonize
sleep 0.5

# Test

echo
echo "*** netns-to-netns TCP latency test ***"
echo

run_client() {
        ip netns exec B \
           sockperf throughput -i 10.0.0.1 --tcp --time 30 \
           --sender-affinity 0 --receiver-affinity 1 --msg-size=1472
}

run_client

echo
echo "*** netns-to-netns TCP latency test WITH sockmap bypass ***"
echo

bpftool cgroup attach \
        /sys/fs/cgroup/unified/test.slice \
        cgroup_sock_ops \
        pinned /sys/fs/bpf/test/sockops_prog

run_client

echo
echo "*** netns-to-netns TCP latency test WITH sockmap bypass + F_PERMANENT ***"
echo

bpftool prog detach \
        pinned /sys/fs/bpf/test/sk_msg_prog \
        sk_msg_verdict \
        pinned /sys/fs/bpf/test/sock_map

bpftool prog attach \
        pinned /sys/fs/bpf/test/sk_msg_prog_once \
        sk_msg_verdict \
        pinned /sys/fs/bpf/test/sock_map

run_client

# Teardown

bpftool prog show

ip netns pids A | xargs kill 2> /dev/null || true
ip netns pids B | xargs kill 2> /dev/null || true

ip netns del A
ip netns del B

rm /sys/fs/bpf/test/*
