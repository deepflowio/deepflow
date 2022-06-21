/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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

#ifndef _ATOMIC_X86_H_
#define _ATOMIC_X86_H_

#include <stdint.h>

/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int32_t cnt;
			      /**< An internal counter value. */
} atomic32_t;

/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int64_t cnt;
			       /**< Internal counter value. */
} atomic64_t;

/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define compiler_barrier() do {             \
  asm volatile ("" : : : "memory");       \
} while(0)

#if MAX_LCORE == 1
#define MPLOCKED			/**< No need to insert MP lock prefix. */
#else
#define MPLOCKED        "lock ; "	/**< Insert MP lock prefix. */
#endif

/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define compiler_barrier() do {             \
  asm volatile ("" : : : "memory");       \
} while(0)

#define mb() _mm_mfence()

#define wmb() _mm_sfence()

#define rmb() _mm_lfence()

#define smp_mb() mb()

#define smp_wmb() compiler_barrier()

#define smp_rmb() compiler_barrier()

#define io_mb() mb()

#define io_wmb() compiler_barrier()

/*------------------------- 32 bit atomic operations -------------------------*/

static inline int
atomic32_cmpset(volatile uint32_t * dst, uint32_t exp, uint32_t src)
{
	uint8_t res;

	asm volatile (MPLOCKED "cmpxchgl %[src], %[dst];" "sete %[res];":[res] "=a"(res),	/* output */
		      [dst] "=m"(*dst)
		      :[src] "r"(src),	/* input */
		      "a"(exp), "m"(*dst)
		      :"memory");	/* no-clobber list */
	return res;
}

static inline int atomic32_test_and_set(atomic32_t * v)
{
	return atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

static inline int
atomic64_cmpset(volatile uint64_t * dst, uint64_t exp, uint64_t src)
{
	uint8_t res;

	asm volatile (MPLOCKED "cmpxchgq %[src], %[dst];" "sete %[res];":[res] "=a"(res),	/* output */
		      [dst] "=m"(*dst)
		      :[src] "r"(src),	/* input */
		      "a"(exp), "m"(*dst)
		      :"memory");	/* no-clobber list */

	return res;
}

static inline void atomic64_init(atomic64_t * v)
{
	v->cnt = 0;
}

static inline int64_t atomic64_read(atomic64_t * v)
{
	return v->cnt;
}

static inline void atomic64_set(atomic64_t * v, int64_t new_value)
{
	v->cnt = new_value;
}

static inline void atomic64_add(atomic64_t * v, int64_t inc)
{
	asm volatile (MPLOCKED "addq %[inc], %[cnt]":[cnt] "=m"(v->cnt)	/* output */
		      :[inc] "ir"(inc),	/* input */
		      "m"(v->cnt)
	    );
}

static inline void atomic64_sub(atomic64_t * v, int64_t dec)
{
	asm volatile (MPLOCKED "subq %[dec], %[cnt]":[cnt] "=m"(v->cnt)	/* output */
		      :[dec] "ir"(dec),	/* input */
		      "m"(v->cnt)
	    );
}

static inline void atomic64_inc(atomic64_t * v)
{
	asm volatile (MPLOCKED "incq %[cnt]":[cnt] "=m"(v->cnt)	/* output */
		      :"m"(v->cnt)	/* input */
	    );
}

static inline void atomic64_dec(atomic64_t * v)
{
	asm volatile (MPLOCKED "decq %[cnt]":[cnt] "=m"(v->cnt)	/* output */
		      :"m"(v->cnt)	/* input */
	    );
}

static inline int atomic64_dec_and_test(atomic64_t * v)
{
	uint8_t ret;

	asm volatile (MPLOCKED "decq %[cnt] ; " "sete %[ret]":[cnt] "+m"(v->cnt),	/* output */
		      [ret] "=qm"(ret)
	    );
	return ret != 0;
}

static inline int atomic64_test_and_set(atomic64_t * v)
{
	return atomic64_cmpset((volatile uint64_t *)&v->cnt, 0, 1);
}

static inline void atomic64_clear(atomic64_t * v)
{
	v->cnt = 0;
}

#endif /* _ATOMIC_X86_H_ */
