#include <linux/bpf.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Map local port in host byte order to target socket */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
	__u32 lport = msg->local_port;

	return bpf_msg_redirect_hash(msg, &sock_map, &lport, BPF_F_INGRESS);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *ctx)
{
	__u32 lport = bpf_ntohl(ctx->remote_port);

	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_printk("map lport:%u to sk:%lx\n", lport, bpf_get_socket_cookie(ctx));
		bpf_sock_hash_update(ctx, &sock_map, &lport, BPF_ANY);
		break;
	}

	return SK_PASS;
}

