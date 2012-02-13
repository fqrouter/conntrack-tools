#ifndef _TIPC_H_
#define _TIPC_H_

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/tipc.h>

/* TODO: no buffer tuning supported. */

struct tipc_conf {
	int ipproto;
	int msgImportance;
	struct {
		uint32_t type;
		uint32_t instance;
	} client;
	struct {
		uint32_t type;
		uint32_t instance;
	} server;
};

struct tipc_stats {
#ifdef CTD_TIPC_DEBUG
	uint64_t returned_messages; /* used for debug purposes */
#endif
	uint64_t bytes;
	uint64_t messages;
	uint64_t error;
};

struct tipc_sock {
	int fd;
	struct sockaddr_tipc addr;
	socklen_t sockaddr_len;
	struct tipc_stats stats;
};

struct tipc_sock *tipc_server_create(struct tipc_conf *conf);
void tipc_server_destroy(struct tipc_sock *m);

struct tipc_sock *tipc_client_create(struct tipc_conf *conf);
void tipc_client_destroy(struct tipc_sock *m);

ssize_t tipc_send(struct tipc_sock *m, const void *data, int size);
ssize_t tipc_recv(struct tipc_sock *m, void *data, int size);

int tipc_get_fd(struct tipc_sock *m);
int tipc_isset(struct tipc_sock *m, fd_set *readfds);

int tipc_snprintf_stats(char *buf, size_t buflen, char *ifname,
		       struct tipc_stats *s, struct tipc_stats *r);

int tipc_snprintf_stats2(char *buf, size_t buflen, const char *ifname,
			const char *status, int active,
			struct tipc_stats *s, struct tipc_stats *r);

#endif
