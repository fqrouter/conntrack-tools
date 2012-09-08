#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <dlfcn.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "network.h"
#include "proto.h"

static struct sync_test_stats {
	uint32_t pkts;
	uint32_t errors;
	uint32_t skip;

	uint32_t l3_proto_unsupported;
	uint32_t l4_proto_unsupported;
	uint32_t l3_proto_malformed;
	uint32_t l4_proto_malformed;
	uint32_t sync_version_old;
} sync_test_stats;

static int bisect_message(struct nethdr *net, uint32_t remain)
{
	printf("v%u ", net->version);

	if (net->version != CONNTRACKD_PROTOCOL_VERSION) {
		printf("[warning: old version] ");
		sync_test_stats.errors++;
		sync_test_stats.sync_version_old++;
	}

	printf("seq:%u ", net->seq);

	if (net->flags & NET_F_RESYNC)
		printf("RESYNC");
	if (net->flags & NET_F_NACK)
		printf("NACK ");
	if (net->flags & NET_F_ACK)
		printf("ACK ");
	if (net->flags & NET_F_ALIVE)
		printf("ALIVE ");
	if (net->flags & NET_F_HELLO)
		printf("HELLO ");
	if (net->flags & NET_F_HELLO_BACK)
		printf("HELLO BACK ");

	if (IS_ACK(net)) {
		const struct nethdr_ack *h =
			(const struct nethdr_ack *) net;

		if (before(h->to, h->from))
			printf("[warning: bad ACK message] ");

		printf("from: %u to: %u ", h->from, h->to);

	} else if (IS_NACK(net)) {
		const struct nethdr_ack *h =
			(const struct nethdr_ack *) net;

		if (before(h->to, h->from))
			printf("[warning: bad NACK message] ");

		printf("from: %u to: %u ", h->from, h->to);
	}

	if (!IS_DATA(net))
		return 0;

	switch(net->type) {
	case NET_T_STATE_CT_NEW:
		printf("CT-NEW ");
		if (msg2ct(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	case NET_T_STATE_CT_UPD:
		printf("CT-UPD ");
		if (msg2ct(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	case NET_T_STATE_CT_DEL:
		printf("CT-DEL ");
		if (msg2ct(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	case NET_T_STATE_EXP_NEW:
		printf("EXP-NEW ");
		if (msg2exp(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	case NET_T_STATE_EXP_UPD:
		printf("EXP-UPD ");
		if (msg2exp(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	case NET_T_STATE_EXP_DEL:
		printf("EXP-DEL ");
		if (msg2exp(net, remain) < 0)
			printf("[warning: malformed payload] ");
		break;
	default:
		printf("? [warning: unknown type] ");
		break;
	}

	return 0;
}

static int bisect(const uint8_t *pkt, int remain)
{
	int ret = 0;
	struct nethdr *net;

	while (remain > 0) {
		int len;

		net = (struct nethdr *)pkt;

		if (remain < NETHDR_SIZ) {
			printf("[warning: truncated header (%u)]\n", remain);
			break;
		}

		len = ntohs(net->len);
		if (len <= 0) {
			printf("[warning: bad header length]\n");
			break;
		}

		if (len > remain) {
			printf("[warning: truncated packet]\n");
			break;
		}

		if (IS_ACK(net) || IS_NACK(net) || IS_RESYNC(net)) {
			if (remain < NETHDR_ACK_SIZ) {
				printf("[warning: truncated ACK header]\n");
				break;
			}

			if (len < NETHDR_ACK_SIZ) {
				printf("[warning: too small ACK header]\n");
				break;
			}
		} else {
			if (len < NETHDR_SIZ) {
				printf("[warning: truncated header]\n");
				break;
			}
		}

		HDR_NETWORK2HOST(net);

		bisect_message(net, remain);

		pkt += net->len;
		remain -= net->len;

		printf("\n");
	}

	return ret;
}

static int
sync_process_packet(const uint8_t *pkt, int pktlen)
{
	struct proto_l2l3_helper *l3h;
	struct proto_l4_helper *l4h;
	int l3hdr_len, l4hdr_len, l4protonum, tot_len;

	l3h = proto_l2l3_helper_find(pkt, &l4protonum, &l3hdr_len, &tot_len);
	if (l3h == NULL) {
		sync_test_stats.skip++;
		sync_test_stats.l3_proto_unsupported++;
		return -1;
	}

	l4h = proto_l4_helper_find(pkt, l4protonum);
	if (l4h == NULL) {
		sync_test_stats.skip++;
		sync_test_stats.l4_proto_unsupported++;
		return -1;
	}

	pkt += l3h->l2hdr_len;
	pktlen -= l3h->l2hdr_len;

	l3hdr_len = l3h->l3pkt_hdr_len(pkt, &tot_len);
	if (l3hdr_len > pktlen) {
		sync_test_stats.errors++;
		sync_test_stats.l3_proto_malformed++;
		return -1;
	}

	/* skip layer 3 header */
	pkt += l3hdr_len;
	pktlen -= l3hdr_len;

	l4hdr_len = l4h->l4pkt_size(pkt, l3hdr_len);
	if (l4hdr_len > pktlen) {
		sync_test_stats.errors++;
		sync_test_stats.l4_proto_malformed++;
		return -1;
	}

	switch(l4protonum) {
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)pkt;
		if (ntohs(udph->dest) != 3780 &&
		    ntohs(udph->source) != 3780) {
			sync_test_stats.skip++;
			return -1;
		}
		break;
	}
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)pkt;
		if (ntohs(tcph->dest) != 3780 &&
		    ntohs(tcph->source) != 3780)
			sync_test_stats.skip++;
			return -1;
		break;
	}
	}

	/* skip layer 4 header */
	pkt += l4hdr_len;
	pktlen -= l4hdr_len;

	/* Ethernet frames that are smaller than 64 bytes are padded. Note
	 * FCS is not included by PCAP files. Discard remaining bytes in the
	 * tail of the packets.
	 */
	if (tot_len + l3h->l2hdr_len < 60)
		pktlen -= (60 - (tot_len + l3h->l2hdr_len));

	bisect(pkt, pktlen);

	return 0;
}

static int
sync_test(const char *pcapfile)
{
	struct pcap_pkthdr pcaph;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt;
	pcap_t *handle;

	handle = pcap_open_offline(pcapfile, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open pcap file %s: %s\n",
				pcapfile, errbuf);
		return -1;
	}
	while ((pkt = pcap_next(handle, &pcaph)) != NULL) {
		sync_test_stats.pkts++;
		sync_process_packet(pkt, pcaph.caplen);
	}

	pcap_close(handle);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Wrong usage:\n");
		fprintf(stderr, "%s <pcap_file>\n",
				argv[0]);
		fprintf(stderr, "example: %s file.pcap\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Initialization of supported layer 3 and 4 protocols here. */
	l2l3_ipv4_init();
	l4_tcp_init();
	l4_udp_init();

	if (sync_test(argv[1]) < 0)
		ret = EXIT_FAILURE;
	else
		ret = EXIT_SUCCESS;

	printf("\e[1;34mDone. packets=%d errors=%d skip=%d\e[0m\n",
		sync_test_stats.pkts, sync_test_stats.errors,
		sync_test_stats.skip);

	return ret;
}
