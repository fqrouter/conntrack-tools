/*
 * (C) 2012 by Quentin Aebischer <quentin.aebicher@usherbrooke.ca>
 *
 * Derived work based on channel_mcast.c from: 
 * 
 * (C) 2006-2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <libnfnetlink/libnfnetlink.h>

#include "channel.h"
#include "tipc.h"

static void
*channel_tipc_open(void *conf)
{
	struct tipc_channel *m;
	struct tipc_conf *c = conf;

	m = calloc(sizeof(struct tipc_channel), 1);
	if (m == NULL)
		return NULL;

	m->client = tipc_client_create(c);
	if (m->client == NULL) {
		free(m);
		return NULL;
	}

	m->server = tipc_server_create(c);
	if (m->server == NULL) {
		tipc_client_destroy(m->client);
		free(m);
		return NULL;
	}
	return m;
}

static int
channel_tipc_send(void *channel, const void *data, int len)
{
	struct tipc_channel *m = channel;
	return tipc_send(m->client, data, len);
}

static int
channel_tipc_recv(void *channel, char *buf, int size)
{
	struct tipc_channel *m = channel;
	return tipc_recv(m->server, buf, size);
}

static void
channel_tipc_close(void *channel)
{
	struct tipc_channel *m = channel;
	tipc_client_destroy(m->client);
	tipc_server_destroy(m->server);
	free(m);
}

static int
channel_tipc_get_fd(void *channel)
{
	struct tipc_channel *m = channel;
	return tipc_get_fd(m->server);
}

static void
channel_tipc_stats(struct channel *c, int fd)
{
	struct tipc_channel *m = c->data;
	char ifname[IFNAMSIZ], buf[512];
	int size;

	if_indextoname(c->channel_ifindex, ifname);
	size = tipc_snprintf_stats(buf, sizeof(buf), ifname,
				    &m->client->stats, &m->server->stats);
	send(fd, buf, size, 0);
}

static void
channel_tipc_stats_extended(struct channel *c, int active,
			     struct nlif_handle *h, int fd)
{
	struct tipc_channel *m = c->data;
	char ifname[IFNAMSIZ], buf[512];
	const char *status;
	unsigned int flags;
	int size;

	if_indextoname(c->channel_ifindex, ifname);
	nlif_get_ifflags(h, c->channel_ifindex, &flags);
	/* 
	 * IFF_UP shows administrative status
	 * IFF_RUNNING shows carrier status
	 */
	if (flags & IFF_UP) {
		if (!(flags & IFF_RUNNING))
			status = "NO-CARRIER";
		else
			status = "RUNNING";
	} else {
		status = "DOWN";
	}
	size = tipc_snprintf_stats2(buf, sizeof(buf),
				     ifname, status, active,
				     &m->client->stats,
				     &m->server->stats);
	send(fd, buf, size, 0);
}

static int
channel_tipc_isset(struct channel *c, fd_set *readfds)
{
	struct tipc_channel *m = c->data;
	return tipc_isset(m->server, readfds);
}

static int
channel_tipc_accept_isset(struct channel *c, fd_set *readfds)
{
	return 0;
}

struct channel_ops channel_tipc = {
	.headersiz	= 60, /* IP header (20 bytes) + tipc unicast name message header 40 (bytes) (see http://tipc.sourceforge.net/doc/tipc_message_formats.html for details) */
	.open		= channel_tipc_open,
	.close		= channel_tipc_close,
	.send		= channel_tipc_send,
	.recv		= channel_tipc_recv,
	.get_fd		= channel_tipc_get_fd,
	.isset		= channel_tipc_isset,
	.accept_isset	= channel_tipc_accept_isset,
	.stats		= channel_tipc_stats,
	.stats_extended = channel_tipc_stats_extended,
};
