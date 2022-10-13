/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "ring.h"
#include "log.h"

#define MAX_TAILQ 64
/**
 * Macro to define a per lcore variable "var" of type "type", don't
 * use keywords like "static" or "volatile" in type, just prefix the
 * whole macro.
 */
#define DEFINE_PER_LCORE(type, name)			\
	__thread __typeof__(type) per_lcore_##name

/**
 * Macro to declare an extern per lcore variable "var" of type "type"
 */
#define DECLARE_PER_LCORE(type, name)			\
	extern __thread __typeof__(type) per_lcore_##name

DECLARE_PER_LCORE(int, _errno);	/**< Per core error number. */

/**
 * Read/write the per-lcore variable value
 */
#define PER_LCORE(name) (per_lcore_##name)

/**
 * Error number value, stored per-thread, which can be queried after
 * calls to certain functions to determine why those functions failed.
 *
 * Uses standard values from errno.h wherever possible, with a small number
 * of additional possible values for RTE-specific conditions.
 */
#ifndef errno
#define errno PER_LCORE(_errno)
#endif

DEFINE_PER_LCORE(int, _errno);

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/* return the size of memory occupied by a ring */
ssize_t ring_get_memsize(unsigned count)
{
	ssize_t sz;

	/* count must be a power of 2 */
	if ((!POWEROF2(count)) || (count > RING_SZ_MASK)) {
		printf("POWEROF2(%d) = %d\n", count, POWEROF2(count));
		ebpf_info(
			  "Requested size is invalid, must be power of 2, and "
			  "do not exceed the size limit %u\n", RING_SZ_MASK);
		return -EINVAL;
	}

	sz = sizeof(struct ring) + count * sizeof(void *);
	sz = ALIGN(sz, CACHE_LINE_SIZE);
	return sz;
}

int
ring_init(struct ring *r, const char *name, unsigned count,
	      unsigned flags)
{
	int ret;

	/* compilation-time checks */
	BUILD_BUG_ON((sizeof(struct ring) & CACHE_LINE_MASK) != 0);
	BUILD_BUG_ON((offsetof(struct ring, cons) &
			  CACHE_LINE_MASK) != 0);
	BUILD_BUG_ON((offsetof(struct ring, prod) &
			  CACHE_LINE_MASK) != 0);

	/* init the ring structure */
	memset(r, 0, sizeof(*r));
	ret = snprintf(r->name, sizeof(r->name), "%s", name);
	if (ret < 0 || ret >= (int)sizeof(r->name))
		return -ENAMETOOLONG;
	r->flags = flags;
	r->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
	r->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

	if (flags & RING_F_EXACT_SZ) {
		r->size = align32pow2(count + 1);
		r->mask = r->size - 1;
		r->capacity = count;
	} else {
		if ((!POWEROF2(count)) || (count > RING_SZ_MASK)) {
			ebpf_info(
				  "Requested size is invalid, must be power of 2, and not exceed the size limit %u\n",
				  RING_SZ_MASK);
			return -EINVAL;
		}
		r->size = count;
		r->mask = count - 1;
		r->capacity = r->mask;
	}
	r->prod.head = r->cons.head = 0;
	r->prod.tail = r->cons.tail = 0;

	return 0;
}

/* create the ring */
struct ring *ring_create(const char *name, unsigned count,
				 int socket_id, unsigned flags)
{
	struct ring *r;
	ssize_t ring_size;
	const unsigned int requested_count = count;

	/* for an exact size ring, round up from count to a power of two */
	if (flags & RING_F_EXACT_SZ)
		count = align32pow2(count + 1);

	ring_size = ring_get_memsize(count);
	if (ring_size < 0) {
		errno = ring_size;
		return NULL;
	}

	/* reserve a memory zone for this ring. If we can't get config or
	 * we are secondary process, the memzone_reserve function will set
	 * errno for us appropriately - hence no check in this this function */
	r = calloc(ring_size, 1);
	if (r != NULL) {
		/* no need to check return value here, we already checked the
		 * arguments above */
		ring_init(r, name, requested_count, flags);

	} else {
		r = NULL;
		ebpf_info("Cannot reserve memory\n");
	}

	return r;
}

/* free the ring */
void ring_free(struct ring *r)
{
	if (r == NULL)
		return;

	free(r);
}

/* dump the status of the ring on the console */
void ring_dump(FILE * f, const struct ring *r)
{
	fprintf(f, "ring <%s>@%p\n", r->name, r);
	fprintf(f, "  flags=%x\n", r->flags);
	fprintf(f, "  size=%" PRIu32 "\n", r->size);
	fprintf(f, "  capacity=%" PRIu32 "\n", r->capacity);
	fprintf(f, "  ct=%" PRIu32 "\n", r->cons.tail);
	fprintf(f, "  ch=%" PRIu32 "\n", r->cons.head);
	fprintf(f, "  pt=%" PRIu32 "\n", r->prod.tail);
	fprintf(f, "  ph=%" PRIu32 "\n", r->prod.head);
	fprintf(f, "  used=%u\n", ring_count(r));
	fprintf(f, "  avail=%u\n", ring_free_count(r));
}
