#include <linux/bpf.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

char _license[] SEC("license") = "GPL";

#define IP4(a, b, c, d)					\
	bpf_htonl((((__u32)(a) & 0xffU) << 24) |	\
		  (((__u32)(b) & 0xffU) << 16) |	\
		  (((__u32)(c) & 0xffU) <<  8) |	\
		  (((__u32)(d) & 0xffU) <<  0))

#define TEST_NET_1_ADDR IP4(192,   0,   2, 0)
#define TEST_NET_1_MASK IP4(255, 255, 255, 0)

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{
	if (msg->family != AF_INET)
		return SK_PASS;

	bpf_printk("sk_msg: remote_ip4=%u\n", msg->remote_ip4);
	
	if ((msg->remote_ip4 & TEST_NET_1_MASK) != TEST_NET_1_ADDR)
		return SK_PASS;
	/* Drop anything destined to 192.0.2.0/24 documentation range */
	return SK_DROP;
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *ctx)
{
	if (ctx->family != AF_INET)
		return SK_PASS;
	if (!ctx->sk)
		return SK_PASS;
	if (ctx->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
		return SK_PASS;

	bpf_printk("sock_ops: event=%d\n", BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB);

	bpf_sock_map_update(ctx, &sock_map, &(__u32){ 0 }, BPF_ANY);

	return SK_PASS;
}

SEC("sockops")
int sockops_prog2(struct bpf_sock_ops *ctx)
{
	if (ctx->family != AF_INET)
		return SK_PASS;
	if (!ctx->sk)
		return SK_PASS;

	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_map_update(ctx, &sock_map, &(__u32){ 0 }, BPF_ANY);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_map_update(ctx, &sock_map, &(__u32){ 1 }, BPF_ANY);
		break;
	}

	return SK_PASS;
}

