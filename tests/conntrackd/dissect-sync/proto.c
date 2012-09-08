#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "linux_list.h"
#include "proto.h"

static LIST_HEAD(l2l3_helper_list);
static LIST_HEAD(l4_helper_list);

struct proto_l2l3_helper *
proto_l2l3_helper_find(const uint8_t *pkt,
				unsigned int *l4protonum,
				unsigned int *l3hdr_len,
				unsigned int *l3hdr_tot_len)
{
	const struct ethhdr *eh = (const struct ethhdr *)pkt;
	struct proto_l2l3_helper *cur;

	list_for_each_entry(cur, &l2l3_helper_list, head) {
		if (ntohs(cur->l2protonum) == eh->h_proto) {
			*l4protonum = cur->l4pkt_proto(pkt + ETH_HLEN);
			*l3hdr_len = cur->l3pkt_hdr_len(pkt + ETH_HLEN,
					l3hdr_tot_len);
			return cur;
		}
	}
	return NULL;
}

void proto_l2l3_helper_register(struct proto_l2l3_helper *h)
{
	list_add(&h->head, &l2l3_helper_list);
}

struct proto_l4_helper *
proto_l4_helper_find(const uint8_t *pkt, unsigned int l4protocol)
{
	struct proto_l4_helper *cur;

	list_for_each_entry(cur, &l4_helper_list, head) {
		if (cur->l4protonum == l4protocol)
			return cur;
	}
	return NULL;
}

void proto_l4_helper_register(struct proto_l4_helper *h)
{
	list_add(&h->head, &l4_helper_list);
}
