/*
 * (C) 2006-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2011 by Vyatta Inc. <http://www.vyatta.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef ssizeof
#define ssizeof(x) (int)sizeof(x)
#endif

#ifndef NFCT_HELPER_NAME_MAX
#define NFCT_HELPER_NAME_MAX	16
#endif

struct nfct_attr_grp_ipv4 {
	u_int32_t src, dst;
};

struct nfct_attr_grp_ipv6 {
	u_int32_t src[4], dst[4];
};

struct nfct_attr_grp_port {
	u_int16_t sport, dport;
};

static void ct_parse_u8(int attr, void *data);
static void ct_parse_u16(int attr, void *data);
static void ct_parse_u32(int attr, void *data);
static void ct_parse_str(int attr, void *data);
static void ct_parse_group(int attr, void *data);
static void ct_parse_nat_seq_adj(int attr, void *data);

struct ct_parser {
	void	(*parse)(int attr, void *data);
	int	size;
	int	max_size;
};

static struct ct_parser h[NTA_MAX] = {
	[NTA_IPV4] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_IPV6] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv6)),
	},
	[NTA_PORT] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_L4PROTO] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_TCP_STATE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_STATUS] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_MARK] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_TIMEOUT] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_MASTER_IPV4] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_MASTER_IPV6] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv6)),
	},
	[NTA_MASTER_L4PROTO] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_MASTER_PORT] = {
		.parse	= ct_parse_group,
		.size	= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_SNAT_IPV4]	= {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_DNAT_IPV4] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_SPAT_PORT]	= {
		.parse	= ct_parse_u16,
		.size	= NTA_SIZE(sizeof(uint16_t)),
	},
	[NTA_DPAT_PORT]	= {
		.parse	= ct_parse_u16,
		.size	= NTA_SIZE(sizeof(uint16_t)),
	},
	[NTA_NAT_SEQ_ADJ] = {
		.parse	= ct_parse_nat_seq_adj,
		.size	= NTA_SIZE(sizeof(struct nta_attr_natseqadj)),
	},
	[NTA_SCTP_STATE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_SCTP_VTAG_ORIG] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_SCTP_VTAG_REPL] = {
		.parse	= ct_parse_u32,
		.size	= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_DCCP_STATE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_DCCP_ROLE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_ICMP_TYPE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_ICMP_CODE] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_ICMP_ID] = {
		.parse	= ct_parse_u16,
		.size	= NTA_SIZE(sizeof(uint16_t)),
	},
	[NTA_TCP_WSCALE_ORIG] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_TCP_WSCALE_REPL] = {
		.parse	= ct_parse_u8,
		.size	= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_HELPER_NAME] = {
		.parse	= ct_parse_str,
		.max_size = NFCT_HELPER_NAME_MAX,
	},
};

static void
ct_parse_u8(int attr, void *data)
{
	uint8_t *value = (uint8_t *) data;
	printf("%u ", *value);
}

static void
ct_parse_u16(int attr, void *data)
{
	uint16_t *value = (uint16_t *) data;
	printf("%u ", ntohs(*value));
}

static void
ct_parse_u32(int attr, void *data)
{
	uint32_t *value = (uint32_t *) data;
	printf("%u ", ntohl(*value));
}

static void
ct_parse_str(int attr, void *data)
{
	printf("%s ", (char *)data);
}

static void
ct_parse_group(int attr, void *data)
{
	/* XXX */
	printf(" ");
}

static void
ct_parse_nat_seq_adj(int attr, void *data)
{
	/* XXX */
	printf(" ");
}

int msg2ct(struct nethdr *net, size_t remain)
{
	int len;
	struct netattr *attr;

	if (remain < net->len) {
		printf("[warning: truncated payload (len=%d)\n", remain);
		return -1;
	}

	len = net->len - NETHDR_SIZ;
	attr = NETHDR_DATA(net);

	printf("attrs=[ ");

	while (len > ssizeof(struct netattr)) {
		ATTR_NETWORK2HOST(attr);
		if (attr->nta_len > len) {
			printf("[warning: too small attribute length (attr=%u)\n",
				attr->nta_attr);
			return -1;
		}
		if (attr->nta_attr > NTA_MAX) {
			printf("[warning: wrong attribute type (attr=%u)\n",
				attr->nta_attr);
			return -1;
		}
		if (h[attr->nta_attr].size &&
		    attr->nta_len != h[attr->nta_attr].size) {
			printf("[warning: wrong attribute length (attr=%u)\n",
				attr->nta_attr);
			return -1;
		}
		if (h[attr->nta_attr].max_size &&
		    attr->nta_len > h[attr->nta_attr].max_size) {
			printf("[warning: too big attribute length (attr=%u) "
			       "len=%u>max=%u]\n",
				attr->nta_attr, attr->nta_len,
				h[attr->nta_attr].max_size);
			return -1;
		}
		if (h[attr->nta_attr].parse == NULL) {
			printf("[warning: skipping unknown attribute (attr=%u)\n",
				attr->nta_attr);
			attr = NTA_NEXT(attr, len);
			continue;
		}
		h[attr->nta_attr].parse(attr->nta_attr, NTA_DATA(attr));

		printf("%u=", attr->nta_attr);

		attr = NTA_NEXT(attr, len);
	}
	printf("] ");

	return 0;
}

static void exp_parse_ct_group(int attr, void *data);
static void exp_parse_ct_u8(int attr, void *data);
static void exp_parse_u32(int attr, void *data);
static void exp_parse_str(int attr, void *data);

static struct exp_parser {
	void	(*parse)(int attr, void *data);
	int	size;
	int	max_size;
} exp_h[NTA_EXP_MAX] = {
	[NTA_EXP_MASTER_IPV4] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_EXP_MASTER_IPV6] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv6)),
	},
	[NTA_EXP_MASTER_L4PROTO] = {
		.parse		= exp_parse_ct_u8,
		.size		= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_EXP_MASTER_PORT] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_EXP_EXPECT_IPV4] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_EXP_EXPECT_IPV6] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv6)),
	},
	[NTA_EXP_EXPECT_L4PROTO] = {
		.parse		= exp_parse_ct_u8,
		.size		= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_EXP_EXPECT_PORT] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_EXP_MASK_IPV4] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_EXP_MASK_IPV6] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv6)),
	},
	[NTA_EXP_MASK_L4PROTO] = {
		.parse		= exp_parse_ct_u8,
		.size		= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_EXP_MASK_PORT] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_EXP_TIMEOUT] = {
		.parse		= exp_parse_u32,
		.size		= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_EXP_FLAGS] = {
		.parse		= exp_parse_u32,
		.size		= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_EXP_CLASS] = {
		.parse		= exp_parse_u32,
		.size		= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_EXP_NAT_IPV4] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_ipv4)),
	},
	[NTA_EXP_NAT_L4PROTO] = {
		.parse		= exp_parse_ct_u8,
		.size		= NTA_SIZE(sizeof(uint8_t)),
	},
	[NTA_EXP_NAT_PORT] = {
		.parse		= exp_parse_ct_group,
		.size		= NTA_SIZE(sizeof(struct nfct_attr_grp_port)),
	},
	[NTA_EXP_NAT_DIR] = {
		.parse		= exp_parse_u32,
		.size		= NTA_SIZE(sizeof(uint32_t)),
	},
	[NTA_EXP_HELPER_NAME] = {
		.parse		= exp_parse_str,
		.max_size	= NFCT_HELPER_NAME_MAX,
	},
	[NTA_EXP_FN] = {
		.parse		= exp_parse_str,
		.max_size	= 32,	/* XXX: artificial limit */
	},
};

static void exp_parse_ct_group(int attr, void *data)
{
	/* XXX */
	printf(" ");
}

static void exp_parse_ct_u8(int attr, void *data)
{
	uint8_t *value = (uint8_t *) data;
	printf("%u ", *value);
}

static void exp_parse_u32(int attr, void *data)
{
	uint32_t *value = (uint32_t *) data;
	printf("%u ", ntohl(*value));
}

static void exp_parse_str(int attr, void *data)
{
	printf("%s ", (char *)data);
}

int msg2exp(struct nethdr *net, size_t remain)
{
	int len;
	struct netattr *attr;

	if (remain < net->len) {
		printf("[warning: truncated payload (len=%d)\n", remain);
		return -1;
	}

	len = net->len - NETHDR_SIZ;
	attr = NETHDR_DATA(net);

	printf("attrs=[ ");

	while (len > ssizeof(struct netattr)) {
		ATTR_NETWORK2HOST(attr);
		if (attr->nta_len > len) {
			printf("[warning: too small attribute length (attr=%u)\n",
				attr->nta_attr);
			goto err;
		}
		if (attr->nta_attr > NTA_MAX) {
			printf("[warning: wrong attribute type (attr=%u)\n",
				attr->nta_attr);
			goto err;
		}
		if (exp_h[attr->nta_attr].size &&
		    attr->nta_len != exp_h[attr->nta_attr].size) {
			printf("[warning: wrong attribute length (attr=%u)\n",
				attr->nta_attr);
			goto err;
		}
		if (exp_h[attr->nta_attr].max_size &&
		    attr->nta_len > exp_h[attr->nta_attr].max_size) {
			printf("[warning: too big attribute length (attr=%u) "
			       "len=%u>max=%u]\n",
				attr->nta_attr, attr->nta_len,
				exp_h[attr->nta_attr].max_size);
			goto err;
		}
		if (exp_h[attr->nta_attr].parse == NULL) {
			printf("[warning: skipping unknown attribute (attr=%u)\n",
				attr->nta_attr);
			attr = NTA_NEXT(attr, len);
			continue;
		}
		exp_h[attr->nta_attr].parse(attr->nta_attr, NTA_DATA(attr));
		printf("%u=", attr->nta_attr);
		attr = NTA_NEXT(attr, len);
	}
	printf("] ");

	return 0;
err:
	return -1;
}
