/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_h
#define included_clib_h

#include "types.h"
#include "log.h"

#define BITS(x)		(8*sizeof(x))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))
#endif

#define always_inline static inline __attribute__ ((__always_inline__))
#define static_always_inline static inline __attribute__ ((__always_inline__))
#define count_leading_zeros(x) __builtin_clzll (x)

#define ASSERT(truth)					\
do {							\
  if (!(truth)) 			                \
    {							\
      ebpf_error ("assertion fails, ", # truth);	\
    }							\
} while (0)

always_inline uword min_log2(uword x)
{
	uword n;
	n = count_leading_zeros(x);
	return BITS(uword) - n - 1;
}

always_inline uword max_log2(uword x)
{
	uword l = min_log2(x);
	if (x > ((uword) 1 << l))
		l++;
	return l;
}

always_inline uword is_pow2(uword x)
{
	return 0 == (x & (x - 1));
}

always_inline uword round_pow2(uword x, uword pow2)
{
	return (x + pow2 - 1) & ~(pow2 - 1);
}

always_inline uword pow2_mask (uword x)
{
//#ifdef __BMI2__
//	return _bzhi_u64 (-1ULL, x);
//#endif
	return ((uword) 1 << x) - (uword) 1;
}

/* Hints to compiler about hot/cold code. */
#define PREDICT_FALSE(x) __builtin_expect((x),0)
#define PREDICT_TRUE(x) __builtin_expect((x),1)
#define COMPILE_TIME_CONST(x) __builtin_constant_p (x)

#define clib_max(x,y)                           \
({                                              \
  __typeof__ (x) _x = (x);                      \
  __typeof__ (y) _y = (y);                      \
  _x > _y ? _x : _y;                            \
})

#define clib_min(x,y)                           \
({                                              \
  __typeof__ (x) _x = (x);                      \
  __typeof__ (y) _y = (y);                      \
  _x < _y ? _x : _y;                            \
})

/* Default cache line size of 64 bytes. */
#ifndef CLIB_LOG2_CACHE_LINE_BYTES
#define CLIB_LOG2_CACHE_LINE_BYTES 6
#endif

#define CLIB_CACHE_LINE_BYTES	  (1 << CLIB_LOG2_CACHE_LINE_BYTES)

/* sanitizers */
#ifdef __has_feature
#if __has_feature(address_sanitizer)
//TODO : suport address_sanitizer
//#define CLIB_SANITIZE_ADDR 1
#endif
#elif defined(__SANITIZE_ADDRESS__)
//#define CLIB_SANITIZE_ADDR 1
#endif

/* Used to pack structure elements. */
#define CLIB_PACKED(x)	x __attribute__ ((packed))
#define CLIB_UNUSED(x)	x __attribute__ ((unused))

#define clib_atomic_fetch_or(a, b) __sync_fetch_and_or(a, b)
#if __x86_64__
#define CLIB_PAUSE() __builtin_ia32_pause ()
#elif defined (__aarch64__) || defined (__arm__)
#define CLIB_PAUSE() __asm__ ("yield")
#else
#define CLIB_PAUSE()
#endif

static_always_inline u8 get_lowest_set_bit_index(uword x)
{
	return uword_bits > 32 ? __builtin_ctzll(x) : __builtin_ctz(x);
}

/*
 * "Population count from Hacker's Delight" is the name of
 * an algorithm that comes from a computer science book called
 * "Hacker's Delight". The book, written by Henry S. Warren,
 * Jr., one of which is the algorithm for counting the
 * number of 1s in the binary representation of an integer, or
 * the so-called "Population count" algorithm. This algorithm
 * is widely used because it is highly efficient and can calculate
 * the number of binary 1s in an integer in a very short time.
 */
always_inline uword count_set_bits(uword x)
{
//#ifdef __POPCNT__
//	return uword_bits >
//	    32 ? __builtin_popcountll(x) : __builtin_popcount(x);
//#else
#if uword_bits == 64
	const uword c1 = 0x5555555555555555;
	const uword c2 = 0x3333333333333333;
	const uword c3 = 0x0f0f0f0f0f0f0f0f;
#else
	const uword c1 = 0x55555555;
	const uword c2 = 0x33333333;
	const uword c3 = 0x0f0f0f0f;
#endif

	/* Sum 1 bit at a time. */
	x = x - ((x >> (uword) 1) & c1);

	/* 2 bits at a time. */
	x = (x & c2) + ((x >> (uword) 2) & c2);

	/* 4 bits at a time. */
	x = (x + (x >> (uword) 4)) & c3;

	/* 8, 16, 32 bits at a time. */
	x = x + (x >> (uword) 8);
	x = x + (x >> (uword) 16);
#if uword_bits == 64
	x = x + (x >> (uword) 32);
#endif

	return x & (2 * BITS(uword) - 1);
//#endif
}

/*
 * Compiler barrier
 *   prevent compiler to reorder memory access across this boundary
 *   prevent compiler to cache values in register (force reload)
 * Not to be confused with CPU memory barrier below
 */
#define CLIB_COMPILER_BARRIER() asm volatile ("":::"memory")

/*
 * Full memory barrier (read and write).
 * To prevent instruction reordering and optimization, ensure that
 * the CPU executes instructions in the order of the code, and also
 * ensure data synchronization in multi-threaded environments.
 */
#define CLIB_MEMORY_BARRIER() __sync_synchronize ()

/*
 * store A
 * CLIB_MEMORY_STORE_BARRIER()
 * store B
 *
 * When B is set, the value of A will be read(another thread).
 * It is important to ensure that the value of A is the latest one.
 */
#if __x86_64__
#define CLIB_MEMORY_STORE_BARRIER() __builtin_ia32_sfence ()
#else
#define CLIB_MEMORY_STORE_BARRIER() __sync_synchronize ()
#endif

always_inline uword
extract_bits (uword x, int start, int count)
{
//#ifdef __BMI__
//	return _bextr_u64 (x, start, count);
//#endif
	return (x >> start) & pow2_mask (count);
}

#endif /* included_clib_h */
