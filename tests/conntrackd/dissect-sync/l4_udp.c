#include <netinet/ip.h>
#include <netinet/udp.h>

#include "proto.h"

static int l4_udp_pkt_size(const uint8_t *pkt, uint32_t dataoff)
{
	return sizeof(struct udphdr);
}

static int l4_udp_pkt_no_data(const uint8_t *pkt)
{
	/* UDP has no control packets. */
	return 1;
}

static struct proto_l4_helper udp = {
	.l4protonum	= IPPROTO_UDP,
	.l4pkt_size	= l4_udp_pkt_size,
	.l4pkt_no_data	= l4_udp_pkt_no_data,
};

void l4_udp_init(void)
{
	proto_l4_helper_register(&udp);
}
