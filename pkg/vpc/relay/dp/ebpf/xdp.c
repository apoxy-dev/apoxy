// SPDX-License-Identifier: AGPL-3.0-only

/* relay_xdp is the XDP program of the relay interface. It drops the packets
 * that the impair map tells it to drop. It gives all other packets to the
 * AF_XDP socket of their queue, as the go-afxdp redirect program does. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* go-afxdp gives its own queue map and XSK map in place of these two. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} qidconf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

/* An LPM trie key: the UDP port of the relay, then the peer. prefixlen counts
 * the 16 bits of the port and then the bits of the peer prefix. */
struct impair_key {
	__u32 prefixlen;
	__u8 port[2];   /* network byte order */
	__u8 addr[16];  /* IPv4 is ::ffff:a.b.c.d */
	__u16 pad;
};

struct impair_value {
	__u64 drop;    /* the drop probability, of 2^32 */
	__u32 delay;   /* µs; the Go send path does the delay */
	__u32 jitter;  /* µs */
	__u64 dropped; /* the packets that the entry dropped */
};

/* Tests write the impair map. In production it is empty. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct impair_key);
	__type(value, struct impair_value);
} impair SEC(".maps");

/* impaired tells if the impair entry of the packet drops it. The key is the
 * destination UDP port and the source address. */
static __always_inline int impaired(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct impair_key key = {.prefixlen = 16 + 128};
	struct impair_value *v;
	struct udphdr *udp;

	if ((void *)(eth + 1) > data_end)
		return 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		/* Only the first fragment has the UDP header. */
		if ((void *)(iph + 1) > data_end || iph->ihl != 5 ||
		    iph->protocol != IPPROTO_UDP ||
		    (iph->frag_off & bpf_htons(0x1fff)))
			return 0;
		key.addr[10] = 0xff;
		key.addr[11] = 0xff;
		__builtin_memcpy(&key.addr[12], &iph->saddr, 4);
		udp = (void *)(iph + 1);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if ((void *)(ip6h + 1) > data_end || ip6h->nexthdr != IPPROTO_UDP)
			return 0;
		__builtin_memcpy(key.addr, &ip6h->saddr, 16);
		udp = (void *)(ip6h + 1);
	} else {
		return 0;
	}
	if ((void *)(udp + 1) > data_end)
		return 0;
	__builtin_memcpy(key.port, &udp->dest, 2);

	v = bpf_map_lookup_elem(&impair, &key);
	if (!v || (__u64)bpf_get_prandom_u32() >= v->drop)
		return 0;
	__sync_fetch_and_add(&v->dropped, 1);
	return 1;
}

SEC("xdp")
int relay_xdp(struct xdp_md *ctx)
{
	__u32 queue = ctx->rx_queue_index;
	__u32 *on;

	if (impaired(ctx))
		return XDP_DROP;
	on = bpf_map_lookup_elem(&qidconf_map, &queue);
	if (!on || !*on)
		return XDP_PASS;
	return bpf_redirect_map(&xsks_map, queue, 0);
}

char _license[] SEC("license") = "GPL";
