// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2048);
} tc_map SEC(".maps");

static int redirect_core(__u32 in_ipaddr)
{
	// TODO: check in_ipaddr to decide redirect_peer or redirect_neigh
	int ret;
	__u32 *redir_target_ifindex;

	redir_target_ifindex = bpf_map_lookup_elem(&tc_map, &in_ipaddr);
	if (redir_target_ifindex == NULL) {
		bpf_printk("Unknown ipaddr %u", in_ipaddr);
		return TCA_ACT_UNSPEC;
	}

	ret = bpf_redirect_peer(*redir_target_ifindex, 0);

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


	return redirect_core(l3->daddr);
}

char __license[] SEC("license") = "GPL";
