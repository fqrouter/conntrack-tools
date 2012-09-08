#ifndef _HELPER_H_
#define _HELPER_H_

#include <stdint.h>

#include "../../../include/linux_list.h"

struct proto_l4_helper {
	struct list_head	head;

	unsigned int		l4protonum;

	int	(*l4pkt_size)(const uint8_t *pkt, uint32_t dataoff);
	int	(*l4pkt_no_data)(const uint8_t *pkt);
};

struct proto_l2l3_helper {
	struct list_head	head;

	unsigned int		l2protonum;
	unsigned int		l2hdr_len;

	unsigned int		l3protonum;

	int	(*l3pkt_hdr_len)(const uint8_t *pkt, int *tot_len);
	int	(*l4pkt_proto)(const uint8_t *pkt);
};

struct proto_l2l3_helper *proto_l2l3_helper_find(const uint8_t *pkt, unsigned int *l4protonum, unsigned int *l3hdr_len, unsigned int *l3hdr_tot_len);
void proto_l2l3_helper_register(struct proto_l2l3_helper *h);

struct proto_l4_helper *proto_l4_helper_find(const uint8_t *pkt, unsigned int l4protonum);
void proto_l4_helper_register(struct proto_l4_helper *h);

/* Initialization of supported protocols here. */
void l2l3_ipv4_init(void);
void l4_tcp_init(void);
void l4_udp_init(void);

#endif
