/*
 *
 * (C) 2012 by Quentin Aebischer <quentin.aebicher@usherbrooke.ca>
 *
 * Derived work based on mcast.c from: 
 * 
 * (C) 2006-2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: tipc socket library
 */


#include "tipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <limits.h>
#include <libnfnetlink/libnfnetlink.h>

#ifdef CTD_TIPC_DEBUG
#include <fcntl.h> /* used for debug purposes */
#endif

struct tipc_sock *tipc_server_create(struct tipc_conf *conf)
{
	struct tipc_sock *m;

#ifdef CTD_TIPC_DEBUG
	int val = 0;
#endif

	m = (struct tipc_sock *) malloc(sizeof(struct tipc_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct tipc_sock));
	m->sockaddr_len = sizeof(struct sockaddr_tipc);

	m->addr.family = AF_TIPC;
	m->addr.addrtype = TIPC_ADDR_NAME;
	m->addr.scope = TIPC_CLUSTER_SCOPE;
	m->addr.addr.name.name.type = conf->server.type;
	m->addr.addr.name.name.instance = conf->server.instance;

	if ((m->fd = socket(AF_TIPC, SOCK_RDM, 0)) == -1) {
		free(m);
		return NULL;
	}

#ifdef CTD_TIPC_DEBUG
	setsockopt(m->fd, SOL_TIPC, TIPC_DEST_DROPPABLE, &val, sizeof(val)); /*used for debug purposes */
#endif
	if (bind(m->fd, (struct sockaddr *) &m->addr, m->sockaddr_len) == -1) {
		close(m->fd);
		free(m);
		return NULL;
	}

	return m;
}

void tipc_server_destroy(struct tipc_sock *m)
{
	close(m->fd);
	free(m);
}

struct tipc_sock *tipc_client_create(struct tipc_conf *conf)
{
	struct tipc_sock *m;

	m = (struct tipc_sock *) malloc(sizeof(struct tipc_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct tipc_sock));

	m->addr.family = AF_TIPC;
	m->addr.addrtype = TIPC_ADDR_NAME;
	m->addr.addr.name.name.type = conf->client.type;
	m->addr.addr.name.name.instance = conf->client.instance;
	m->addr.addr.name.domain = 0;
	m->sockaddr_len = sizeof(struct sockaddr_tipc);

	if ((m->fd = socket(AF_TIPC, SOCK_RDM, 0)) == -1) {
		free(m);
		return NULL;
	}

#ifdef CTD_TIPC_DEBUG
	setsockopt(m->fd, SOL_TIPC, TIPC_DEST_DROPPABLE, &val, sizeof(val));
	fcntl(m->fd, F_SETFL, O_NONBLOCK);
#endif
	setsockopt(m->fd, SOL_TIPC, TIPC_IMPORTANCE,  &conf->msgImportance, sizeof(conf->msgImportance));

	return m;
}

void tipc_client_destroy(struct tipc_sock *m)
{
	close(m->fd);
	free(m);
}

ssize_t tipc_send(struct tipc_sock *m, const void *data, int size)
{
	ssize_t ret;
#ifdef CTD_TIPC_DEBUG
	char buf[50];
#endif

	ret = sendto(m->fd, 
		     data,
		     size,
		     0,
		     (struct sockaddr *) &m->addr,
		     m->sockaddr_len);
	if (ret == -1) {
		m->stats.error++;
		return ret;
	}

#ifdef CTD_TIPC_DEBUG
	if(!recv(m->fd,buf,sizeof(buf),0))
		m->stats.returned_messages++;
#endif

	m->stats.bytes += ret;
	m->stats.messages++;  

	return ret;
}

ssize_t tipc_recv(struct tipc_sock *m, void *data, int size)
{
	ssize_t ret;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	
	ret = recvfrom(m->fd,
		       data, 
		       size,
		       0,
		       (struct sockaddr *)&m->addr,
		       &sin_size);
	if (ret == -1) {
		if (errno != EAGAIN)
			m->stats.error++;
		return ret;
	}

#ifdef CTD_TIPC_DEBUG
	if (!ret)
		m->stats.returned_messages++;
#endif

	m->stats.bytes += ret;
	m->stats.messages++;

	return ret;
}

int tipc_get_fd(struct tipc_sock *m)
{
	return m->fd;
}

int tipc_isset(struct tipc_sock *m, fd_set *readfds)
{
	return FD_ISSET(m->fd, readfds);
}

int
tipc_snprintf_stats(char *buf, size_t buflen, char *ifname,
		     struct tipc_stats *s, struct tipc_stats *r)
{
	size_t size;

	size = snprintf(buf, buflen, "tipc traffic (active device=%s):\n"
				     "%20llu Bytes sent "
				     "%20llu Bytes recv\n"
				     "%20llu Pckts sent "
				     "%20llu Pckts recv\n"
				     "%20llu Error send "
				     "%20llu Error recv\n",
#ifdef CTD_TIPC_DEBUG
				     "%20llu Returned messages\n\n",
#endif
				     ifname,
				     (unsigned long long)s->bytes,
				     (unsigned long long)r->bytes,
				     (unsigned long long)s->messages,
				     (unsigned long long)r->messages,
				     (unsigned long long)s->error,
				     (unsigned long long)r->error)
#ifdef CTD_TIPC_DEBUG
				     (unsigned long long)s->returned_messages);
#else
				     ;
#endif
	return size;
}

int
tipc_snprintf_stats2(char *buf, size_t buflen, const char *ifname, 
		      const char *status, int active,
		      struct tipc_stats *s, struct tipc_stats *r)
{
	size_t size;

	size = snprintf(buf, buflen, 
			"tipc traffic device=%s status=%s role=%s:\n"
			"%20llu Bytes sent "
			"%20llu Bytes recv\n"
			"%20llu Pckts sent "
			"%20llu Pckts recv\n"
			"%20llu Error send "
			"%20llu Error recv\n",
#ifdef CTD_TIPC_DEBUG
			"%20llu Returned messages\n\n",
#endif
			ifname, status, active ? "ACTIVE" : "BACKUP",
			(unsigned long long)s->bytes,
			(unsigned long long)r->bytes,
			(unsigned long long)s->messages,
			(unsigned long long)r->messages,
			(unsigned long long)s->error,
			(unsigned long long)r->error);
#ifdef CTD_TIPC_DEBUG			
			(unsigned long long)s->returned_messages);
#else
			;
#endif
	return size;
}
