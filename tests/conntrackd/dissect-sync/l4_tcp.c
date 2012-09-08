#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "proto.h"

static int l4_tcp_pkt_size(const uint8_t *pkt, uint32_t dataoff)
{
	const struct tcphdr *tcph = (const struct tcphdr *)(pkt + dataoff);

	return tcph->doff << 2;
}

static int l4_tcp_pkt_no_data(const uint8_t *pkt)
{
	const struct tcphdr *tcph = (const struct tcphdr *)pkt;
	return tcph->syn || tcph->fin || tcph->rst || !tcph->psh;
}

static struct proto_l4_helper tcp = {
	.l4protonum	= IPPROTO_TCP,
	.l4pkt_size	= l4_tcp_pkt_size,
	.l4pkt_no_data	= l4_tcp_pkt_no_data,
};

void l4_tcp_init(void)
{
	proto_l4_helper_register(&tcp);
}
