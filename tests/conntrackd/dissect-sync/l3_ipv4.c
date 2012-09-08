#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#include "proto.h"

static int l3_ipv4_pkt_l4proto_num(const uint8_t *pkt)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	return iph->protocol;
}

static int l3_ipv4_pkt_l3hdr_len(const uint8_t *pkt, int *tot_len)
{
	const struct iphdr *iph = (const struct iphdr *)pkt;

	*tot_len = ntohs(iph->tot_len);

	return iph->ihl << 2;
}

static struct proto_l2l3_helper ipv4 = {
	.l2protonum	= ETH_P_IP,
	.l3protonum	= AF_INET,
	.l2hdr_len	= ETH_HLEN,
	.l3pkt_hdr_len	= l3_ipv4_pkt_l3hdr_len,
	.l4pkt_proto	= l3_ipv4_pkt_l4proto_num,
};

void l2l3_ipv4_init(void)
{
	proto_l2l3_helper_register(&ipv4);
}
