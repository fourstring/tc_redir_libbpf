// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/
#define ETH_IFINDEX 2
#define VETH1_IFINDEX 5
#define VETH2_IFINDEX 7
#define VETH1_IPADDR 0x0a000a0a
#define VETH2_IPADDR 0x14000a0a
#define ETH_IPADDR 0xd61fa8c0

// Offset
// Refer to: https://android.googlesource.com/kernel/hikey-linaro/+/refs/heads/master/samples/bpf/tcbpf1_kern.c
// and: https://github.com/torvalds/linux/blob/master/samples/bpf/test_lwt_bpf.c
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SRC_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define UDP_DST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_ID_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, un))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IS_PSEUDO 0x10
#define ETH_HLEN 14

#define QUERY_MASK 0xffff

// NAT query id range
#define DYNAMIC_ID_LOW 30000
#define DYNAMIC_ID_HIGH 55535

// CB MAGIC
#define CB_MAGIC_UDP 

// tuple for (source addr, dynamic l4 id)
typedef struct nattuple {
    __u32 source_addr;
    __u16 l4_id;
    __u16 padding;
} NATtuple;