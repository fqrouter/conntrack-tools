/*
 * (C) 2006-2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Vyatta Inc. <http://www.vyatta.com>
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
 */

#include "netlink.h"
#include "traffic_stats.h"
#include "cache.h"
#include "log.h"
#include "conntrackd.h"
#include "internal.h"
#include "alarm.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct ct_state_track {
	struct cache *cache;
	struct alarm_block track_counter_alarm;
};

static struct ct_state_track *state_track;

struct track_extra {
	struct alarm_block alarm;
	int stamina;
};

static void add_track_alarm(struct alarm_block *a)
{
	long n, m;

	n = random() % 60 + 1;
	m = ((random() % 5 + 1)  * 200000) - 1;

	/* Check again in [0, 60] secs if that entry is still there */
	add_alarm(a, n, m);
}

static void timeout(struct alarm_block *a, void *data)
{
	struct cache_object *obj = data;
	struct track_extra *x = cache_get_extra(obj);

	STATE(get_retval) = 0;
	nl_get_conntrack(STATE(get), obj->ptr);
	if (!STATE(get_retval)) {
		/* That entry does not seem to be in the kernel anymore */
		if (x->stamina-- <= 0) {
			/* Too many tries, log this entry, it has vanished */
			dlog_ct(STATE(log), obj->ptr, NFCT_O_PLAIN);
			cache_del(obj->cache, obj);
			cache_object_free(obj);
			return;
		}
	}
	add_track_alarm(&x->alarm);
}

static void track_timer_add(struct cache_object *obj, void *data)
{
	struct track_extra *x = data;

	init_alarm(&x->alarm, obj, timeout);
	add_track_alarm(&x->alarm);
	x->stamina = 5;
}

static void track_timer_update(struct cache_object *obj, void *data)
{
	struct track_extra *x = data;

	add_track_alarm(&x->alarm);
}

static void track_timer_destroy(struct cache_object *obj, void *data)
{
	struct track_extra *x = data;

	del_alarm(&x->alarm);
}

static int track_timer_dump(struct cache_object *obj, void *data, char *buf, int type)
{
	struct timeval tv, tmp;
	struct track_extra *x = data;

	if (type == NFCT_O_XML)
		return 0;

	if (!alarm_pending(&x->alarm))
		return 0;

	gettimeofday(&tv, NULL);
	timersub(&x->alarm.tv, &tv, &tmp);
	return sprintf(buf, " [ping in %lds, stamina %d]", tmp.tv_sec,
			x->stamina);
}

struct cache_extra track_extra = {
	.size		= sizeof(struct track_extra),
	.add		= track_timer_add,
	.update		= track_timer_update,
	.destroy	= track_timer_destroy,
	.dump		= track_timer_dump
};

/* track ct counter every 10 seconds */
#define TRACK_SECS 10

static void track_counter_cb(struct alarm_block *a, void *data)
{
	int fd, ret, ct_kernel_entries, diff;
	char buf[1024];

	fd = open("/proc/sys/net/netfilter/nf_conntrack_count", O_RDONLY);
	if (fd < 0)
		return;

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		return;

	buf[ret-1] = '\0';
	ct_kernel_entries = atoi(buf);

	diff = state_track->cache->stats.active - ct_kernel_entries;

	/* Assume that 160 bytes is the average size of a ctnetlink message.
	 * We have to take into account on-the-fly messages that did not hit
	 * our caching system. The non-acceptable difference between the kernel
	 * and userspace happens if the kernel table contains more entries than
	 * our cache + pending on-the-fly messages.
	 */
	if (diff > (int)(CONFIG(netlink_buffer_size) / 160))
		dlog(LOG_ERR, "The internal cache contains %d entries "
				"more than the kernel\n", diff);

#if 0
	printf("%d entries in the kernel and diff is %d\n",
		ct_kernel_entries, diff);
#endif

	add_alarm(&state_track->track_counter_alarm, TRACK_SECS, 0);

	close(fd);
}

static int init_track(void)
{
	if (CONFIG(flags) & CTD_POLL) {
		dlog(LOG_ERR, "can't use `PollSecs' with `Track'");
		return -1;
	}
	state_track = malloc(sizeof(struct ct_state_track));
	if (state_track == NULL) {
		dlog(LOG_ERR, "can't allocate memory for track");
		return -1;
	}
	memset(state_track, 0, sizeof(struct ct_state_track));

	/* Use cache_stats_ct_ops, it's fine for us */
	state_track->cache = cache_create("track", CACHE_T_CT,
					 &track_extra,
					 &cache_stats_ct_ops);
	if (state_track->cache == NULL) {
		dlog(LOG_ERR, "can't allocate memory for the cache");
		free(state_track);
		return -1;
	}

	init_alarm(&state_track->track_counter_alarm, NULL,
		   track_counter_cb);
	add_alarm(&state_track->track_counter_alarm, TRACK_SECS, 0);

	CONFIG(netlink).events_reliable = 1;
	dlog(LOG_NOTICE, "running in TRACK mode");

	return 0;
}

static void kill_track(void)
{
	cache_destroy(state_track->cache);
}

/* handler for requests coming via UNIX socket */
static int local_handler_track(int fd, int type, void *data)
{
	int ret = LOCAL_RET_OK;

	switch(type) {
	case CT_DUMP_INTERNAL:
		cache_dump(state_track->cache, fd, NFCT_O_PLAIN);
		break;
	case CT_DUMP_INT_XML:
		cache_dump(state_track->cache, fd, NFCT_O_XML);
		break;
	case CT_FLUSH_CACHE:
	case CT_FLUSH_INT_CACHE:
		dlog(LOG_NOTICE, "flushing caches");
		cache_flush(state_track->cache);
		break;
	case KILL:
		killer(0);
		break;
	case STATS:
		cache_stats(state_track->cache, fd);
		dump_traffic_stats(fd);
		break;
	case STATS_CACHE:
		cache_stats_extended(state_track->cache, fd);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static void track_populate(struct nf_conntrack *ct)
{
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_TIMEOUT);
	nfct_attr_unset(ct, ATTR_USE);

	cache_update_force(state_track->cache, ct);
}

static int track_resync(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct,
			void *data)
{
	if (ct_filter_conntrack(ct, 1))
		return NFCT_CB_CONTINUE;

	/* This is required by kernels < 2.6.20 */
	nfct_attr_unset(ct, ATTR_TIMEOUT);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_ORIG_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_BYTES);
	nfct_attr_unset(ct, ATTR_REPL_COUNTER_PACKETS);
	nfct_attr_unset(ct, ATTR_USE);

	cache_update_force(state_track->cache, ct);

	return NFCT_CB_CONTINUE;
}

static void track_event_new(struct nf_conntrack *ct, int origin)
{
	int id;
	struct cache_object *obj;

	nfct_attr_unset(ct, ATTR_TIMEOUT);

	obj = cache_find(state_track->cache, ct, &id);
	if (obj == NULL) {
		obj = cache_object_new(state_track->cache, ct);
		if (obj == NULL)
			return;

		if (cache_add(state_track->cache, obj, id) == -1) {
			cache_object_free(obj);
			return;
		}
	}
	return;
}

static void track_event_upd(struct nf_conntrack *ct, int origin)
{
	nfct_attr_unset(ct, ATTR_TIMEOUT);
	cache_update_force(state_track->cache, ct);
}

static int track_event_del(struct nf_conntrack *ct, int origin)
{
	int id;
	struct cache_object *obj;

	nfct_attr_unset(ct, ATTR_TIMEOUT);

	obj = cache_find(state_track->cache, ct, &id);
	if (obj) {
		cache_del(state_track->cache, obj);
		cache_object_free(obj);
		return 1;
	}
	return 0;
}

static struct internal_handler internal_cache_track = {
	.flags			= INTERNAL_F_POPULATE | INTERNAL_F_RESYNC,
	.ct = {
		.populate		= track_populate,
		.resync			= track_resync,
		.new			= track_event_new,
		.upd			= track_event_upd,
		.del			= track_event_del,
	},
};

struct ct_mode track_mode = {
	.init 			= init_track,
	.local			= local_handler_track,
	.kill			= kill_track,
	.internal		= &internal_cache_track,
};
