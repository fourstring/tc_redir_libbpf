// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/
// #define VETH1_IFINDEX 21
// #define VETH2_IFINDEX 23

// struct bpf_map_def SEC(".maps") tc_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__u32),
// 	.value_size = sizeof(__u32),
// 	.max_entries = 2048,
// };

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2048);
} tc_map SEC(".maps");

// callback for bpf_map_lookup_elem
// struct callback_ctx {
// 	__u32 in_ifindex;
// 	__u32 redir_target_ifindex;
// };

// static u64 callback_fn(struct bpf_map *map, __u32 *ip, __u32 *ifindex, struct callback_ctx *data)
// {
// 	// find the ifindex in tc_map which is different from in_ifindex
// 	if(data->in_ifindex != *ifindex) {
// 		data->redir_target_ifindex = *ifindex;
// 		return 1;
// 	}

// 	return 0;
// }

static int redirect_core(__u32 in_ipaddr)
{
	// TODO: check in_ipaddr to decide redirect_peer or redirect_neigh
	int ret;
	__u32 *redir_target_ifindex;

	// bpf_printk("in_ifindex: %u", in_ifindex);
	// __u32 *temp_ifindex = NULL;
	redir_target_ifindex = bpf_map_lookup_elem(&tc_map, &in_ipaddr);
	if (redir_target_ifindex == NULL) {
		bpf_printk("Unknown ipaddr %u", in_ipaddr);
		return TCA_ACT_UNSPEC;
	}
		// struct callback_ctx cb = {
		// 	// .in_ifindex = in_ifindex,
		// 	.redir_target_ifindex = 0
		// };
		// bpf_for_each_map_elem(&tc_map, callback_fn, &cb, 0);
		// redir_target_ifindex = cb.redir_target_ifindex;
		// bpf_printk("redir_target_ifindex: %u", redir_target_ifindex);


	// if (in_ifindex == VETH1_IFINDEX) {
	// 	redir_target_ifindex = VETH2_IFINDEX;
	// } else if (in_ifindex == VETH2_IFINDEX) {
	// 	redir_target_ifindex = VETH1_IFINDEX;
	// } else {
	// 	bpf_printk("Unknown ifindex %u", in_ifindex);
	// 	return TCA_ACT_UNSPEC;
	// }

	ret = bpf_redirect_peer(*redir_target_ifindex, 0);

	// bpf_printk("redirected from if %u to if %u, ret=%d", in_ifindex, redir_target_ifindex, ret);
	return ret;
}

SEC("tc")
int redirect_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	bpf_printk("[ingress %d] received packet, ctx->protocol=%x", ctx->ifindex, bpf_ntohs(ctx->protocol));

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	__u32 temp = ctx->ifindex; 
	// bpf_map_update_elem(&tc_map, &(l3->saddr), &temp, BPF_ANY);


	return redirect_core(l3->daddr);
}

char __license[] SEC("license") = "GPL";
