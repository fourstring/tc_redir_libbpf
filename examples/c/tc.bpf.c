// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/
#define VETH1_IFINDEX 62
#define VETH2_IFINDEX 64

static int redirect_core(__u32 in_ipaddr, __u32 in_ifindex)
{
	// TODO: check in_ipaddr to decide redirect_peer or redirect_neigh
	int ret;
	__u32 redir_target_ifindex;

	if (in_ifindex == VETH1_IFINDEX) {
		redir_target_ifindex = VETH2_IFINDEX;
	} else if (in_ifindex == VETH2_IFINDEX) {
		redir_target_ifindex = VETH1_IFINDEX;
	} else {
		bpf_printk("Unknown ifindex %u", in_ifindex);
		return TCA_ACT_UNSPEC;
	}

	ret = bpf_redirect_peer(redir_target_ifindex, 0);

	bpf_printk("redirected from if %u to if %u, ret=%d", in_ifindex, redir_target_ifindex, ret);
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

	return redirect_core(ctx->remote_ip4, ctx->ifindex);
}

char __license[] SEC("license") = "GPL";
