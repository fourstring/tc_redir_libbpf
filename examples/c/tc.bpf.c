// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include "tc.h"

static __u16 NEXT_ICMP_ID = DYNAMIC_ID_LOW;
static __u16 NEXT_TCP_ID = DYNAMIC_ID_LOW;
static __u16 NEXT_UDP_ID = DYNAMIC_ID_LOW;

// SNAT table for ICMP usage
// We have two tables: (k <-> v)
// 1. container query id <-> dynamic query id
// 2. dynamic query id <-> ifindex | container query id
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, u16);
} nat_map_icmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, NATtuple);
} nat_map_icmp2 SEC(".maps");

// SNAT table for UDP usage
// 1. container port <-> dynamic port
// 2. dynamic port <-> ifindex | container port
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, u16);
} nat_map_udp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, NATtuple);
} nat_map_udp2 SEC(".maps");

// SNAT table for TCP usage
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, u16);
} nat_map_tcp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100);
	__type(key, u16);
	__type(value, NATtuple);
} nat_map_tcp2 SEC(".maps");

// Net NS communication inner Host
// This situation we don't need any modification for packet.
static inline int redirect_netns(__u32 in_ifindex) {
	int ret;
	ret = bpf_redirect_peer(in_ifindex, 0);

	bpf_printk("redirected to if %u's peer, ret=%d", in_ifindex, ret);
	return ret;
}

// Destination Network Address Translation
// Return the ifindex of the veth
static inline __u32 do_dnat(struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *snat_map;
	__u32 l4_csum_offset = 0, l4_dst_offset = 0, orig_ifindex;
	__u16 dynamic_query_id = 0;
	int ret, flags = IS_PSEUDO;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return 0;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return 0;

	__u32 old_dst_addr = l3->daddr;

	if (l3->protocol == IPPROTO_ICMP) {
		struct icmphdr *l4_icmp;
		l4_icmp = (struct icmphdr *)(l3 + 1);
		if ((void *)(l4_icmp + 1) > data_end)
			return 0;

		snat_map = &nat_map_icmp2;
		dynamic_query_id = l4_icmp->un.echo.id;
		l4_dst_offset = ICMP_ID_OFF;
		l4_csum_offset = ICMP_CSUM_OFF;
	} else if (l3->protocol == IPPROTO_UDP) {
		struct udphdr *l4_udp;
		l4_udp = (struct udphdr *)(l3 + 1);
		if ((void *)(l4_udp + 1) > data_end)
			return TC_ACT_OK;

		snat_map = &nat_map_udp2;
		dynamic_query_id = l4_udp->dest;
		l4_dst_offset = UDP_DST_OFF;
		l4_csum_offset = UDP_CSUM_OFF;
		flags |= BPF_F_MARK_MANGLED_0;
	} else if (l3->protocol == IPPROTO_TCP) {
		struct tcphdr *l4_tcp;
		l4_tcp = (struct tcphdr *)(l3 + 1);
		if ((void *)(l4_tcp + 1) > data_end)
			return TC_ACT_OK;
		
		snat_map = &nat_map_tcp2;
		dynamic_query_id = l4_tcp->dest;
		l4_dst_offset = TCP_DST_OFF;
		l4_csum_offset = TCP_CSUM_OFF;
	}

	// Check the nat table & find the corresponding l4 id
	NATtuple *value = bpf_map_lookup_elem(snat_map, &dynamic_query_id);
	if (!value) {
		// bpf_printk("unable to find query id %d in map", dynamic_query_id);
		return 0;
	}

	if (value->source_addr == VETH1_IPADDR) {
		orig_ifindex = VETH1_IFINDEX;
	} else if (value->source_addr == VETH2_IPADDR) {
		orig_ifindex = VETH2_IFINDEX;
	} else {
		bpf_printk("unknown dst %x", value->source_addr);
		return 0;
	}

	// Csum for layer 4
	// It wouldn't check l4 csum
	// ret = bpf_l4_csum_replace(ctx, l4_csum_offset, dynamic_query_id, value->l4_id, sizeof(__u32) | flags);
	// if (ret < 0) {
	// 	bpf_printk("bpf_l4_csum_replace failed: %d", ret);
	// 	return 0;
	// }

	// Also need to modify the destination address
	ret = bpf_l3_csum_replace(ctx, IP_CSUM_OFF, old_dst_addr, value->source_addr, sizeof(__u32));
	if (ret < 0) {
		bpf_printk("bpf_l3_csum_replace failed: %d", ret);
		return 0;
	}
	
	// change the destination IP address
	bpf_skb_store_bytes(ctx, IP_DST_OFF, &value->source_addr, sizeof(__u32), 0);
	bpf_skb_store_bytes(ctx, l4_dst_offset, &value->l4_id, sizeof(__u16), 0);

	return orig_ifindex;
}

// Source Network Address Translation
static inline int do_snat(struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *snat_map, *snat_map2;
	__u32 l4_csum_offset = 0, l4_src_offset = 0;
	__u16 l4_id = 0, dynamic_query_id, *next_id = NULL;
	int ret, flags = IS_PSEUDO;
	__u8 l4_ip_related = 0;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	__u32 old_src_addr = l3->saddr;
	__u32 new_src_addr = ETH_IPADDR;
	// Do SNAT based on the `l3->protocol`
	if (l3->protocol == IPPROTO_ICMP) {
		struct icmphdr *l4_icmp;
		l4_icmp = (struct icmphdr *)(l3 + 1);
		if ((void *)(l4_icmp + 1) > data_end)
			return TC_ACT_OK;

		l4_csum_offset = ICMP_CSUM_OFF;
		l4_src_offset = ICMP_ID_OFF;
		l4_id = l4_icmp->un.echo.id;
		next_id = &NEXT_ICMP_ID;
		snat_map = &nat_map_icmp;
		snat_map2 = &nat_map_icmp2;
	} else if (l3->protocol == IPPROTO_UDP) {
		struct udphdr *l4_udp;
		l4_udp = (struct udphdr *)(l3 + 1);
		if ((void *)(l4_udp + 1) > data_end)
			return TC_ACT_OK;

		l4_csum_offset = UDP_CSUM_OFF;
		l4_src_offset = UDP_SRC_OFF;
		l4_id = l4_udp->source;
		next_id = &NEXT_UDP_ID;
		snat_map = &nat_map_udp;
		snat_map2 = &nat_map_udp2;
		flags |= BPF_F_MARK_MANGLED_0;
		l4_ip_related = 1;

	} else if (l3->protocol == IPPROTO_TCP) {
		struct tcphdr *l4_tcp;
		l4_tcp = (struct tcphdr *)(l3 + 1);
		if ((void *)(l4_tcp + 1) > data_end)
			return TC_ACT_OK;

		l4_csum_offset = TCP_CSUM_OFF;
		l4_src_offset = TCP_SRC_OFF;
		l4_id = l4_tcp->source;
		next_id = &NEXT_TCP_ID;
		snat_map = &nat_map_tcp;
		snat_map2 = &nat_map_tcp2;
		l4_ip_related = 1;
	} else {
		bpf_printk("unsupported protocol: %x", l3->protocol);
		return TC_ACT_OK;
	}

	if (snat_map == NULL)
		return TC_ACT_OK;

	if (next_id == NULL)
		return TC_ACT_OK;

	// First trying to find a id and allocate one if failed
	void * query_key = bpf_map_lookup_elem(snat_map, &l4_id);
	if (!query_key) {
		dynamic_query_id = *next_id;
		*next_id += 1;
		if (*next_id > DYNAMIC_ID_HIGH) 
			*next_id = DYNAMIC_ID_LOW;

		ret = bpf_map_update_elem(snat_map, &l4_id, &dynamic_query_id, BPF_NOEXIST);
		if (ret < 0) {
			bpf_printk("failed to update map: %d", ret);
			return TC_ACT_OK;
		}

		// Also constructing the map between dynamic_id and ifindex & old_id
		NATtuple value;
		value.source_addr = old_src_addr;
		value.l4_id = l4_id;
		value.padding = 0;
		
		ret = bpf_map_update_elem(snat_map2, &dynamic_query_id, &value, BPF_NOEXIST);
		if (ret < 0) {
			bpf_printk("failed to update map: %d", ret);
			return TC_ACT_OK;
		}
	} else {
		dynamic_query_id = *(__u16 *)query_key;
	}

	if (l4_ip_related) {
		ret = bpf_l4_csum_replace(ctx, l4_csum_offset, old_src_addr, ETH_IPADDR, sizeof(__u32) | flags);
		if (ret < 0) {
			bpf_printk("bpf_l4_csum_replace failed: %d", ret);
			return TC_ACT_OK;
		}

		__u16 csum;
		bpf_skb_load_bytes(ctx, l4_csum_offset, &csum, sizeof(__sum16));
		bpf_printk("new l4 csum 1: %x", csum);
	}

	// Replace the checksum of layer 3
	ret = bpf_l3_csum_replace(ctx, IP_CSUM_OFF, old_src_addr, ETH_IPADDR, sizeof(__u32));
	if (ret < 0) {
		bpf_printk("bpf_l3_csum_replace failed: %d", ret);
		return TC_ACT_OK;
	}

	// Change the src of L3 & L4
	bpf_skb_store_bytes(ctx, IP_SRC_OFF, &new_src_addr, sizeof(__u32), 0);

	// Replace the checksum of layer 4
	ret = bpf_l4_csum_replace(ctx, l4_csum_offset, l4_id, dynamic_query_id, sizeof(__u16));
	if (ret < 0) {
		bpf_printk("bpf_l4_csum_replace failed: %d", ret);
		return TC_ACT_OK;
	}

	__u16 csum;
	bpf_skb_load_bytes(ctx, l4_csum_offset, &csum, sizeof(__sum16));
	bpf_printk("new l4 csum 2: %x", csum);

	bpf_skb_store_bytes(ctx, l4_src_offset, &dynamic_query_id, sizeof(__u16), 0);
 
	return ret;
}

// This is the ingress of veth
SEC("tc")
int redirect_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	int ret;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	bpf_printk("[ingress %d] received packet, ctx->protocol=%x", ctx->ifindex, bpf_ntohs(ctx->protocol));

	// Currently we only care about ipv4 & TCP/UDP/ICMP
	if (bpf_ntohs(ctx->protocol) != ETH_P_IP  || (l3->protocol != IPPROTO_TCP && l3->protocol != IPPROTO_ICMP && l3->protocol != IPPROTO_UDP)) 
		return TC_ACT_OK;

	if (l3->daddr == VETH1_IPADDR) {
		return redirect_netns(VETH1_IFINDEX);
	}

	if (l3->daddr == VETH2_IPADDR) {
		return redirect_netns(VETH2_IFINDEX);
	}

	// Net NS communication outside Host
	do_snat(ctx);

	// After all these done, redirct the packet to eth's neighbor
	ret = bpf_redirect_neigh(ETH_IFINDEX, NULL, 0, 0);

	bpf_printk("redirected to if %u neigh, ret=%d", ETH_IFINDEX, ret);

	return ret;
}

// Engress of eth
SEC("tc")
int redirect_ingress_eth(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	int ret;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	if (bpf_ntohs(ctx->protocol) != ETH_P_IP  || (l3->protocol != IPPROTO_TCP && l3->protocol != IPPROTO_ICMP && l3->protocol != IPPROTO_UDP)) 
		return TC_ACT_OK;

	// TODO: do DNAT
	__u32 in_ifindex = do_dnat(ctx);
	if (in_ifindex == 0) {
		// bpf_printk("failed to do DNAT");
		return TC_ACT_OK;
	}

	ret = bpf_redirect_peer(in_ifindex, 0);

	bpf_printk("redirected to if %u peer 3, ret=%d", in_ifindex, ret);
	return ret;
}

char __license[] SEC("license") = "GPL";
