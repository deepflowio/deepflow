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
  Copyright (c) 2001-2005 Eliot Dresselhaus

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

#ifndef included_clib_types_h
#define included_clib_types_h

typedef signed char i8;
typedef signed short i16;

typedef unsigned char u8;
typedef unsigned short u16;

/* Floating point types. */
typedef double f64;
typedef float f32;

#if defined (__x86_64__)
#ifndef __COVERITY__
typedef signed int i128 __attribute__((mode(TI)));
typedef unsigned int u128 __attribute__((mode(TI)));
#endif
#endif

#if (defined(i386) || (defined(_mips) && __mips != 64) || defined(powerpc) || defined (__SPU__) || defined(__sparc__) || defined(__arm__) || defined (__xtensa__) || defined(__TMS320C6X__))
typedef signed int i32;
typedef signed long long i64;

#ifndef CLIB_AVOID_CLASH_WITH_LINUX_TYPES
typedef unsigned int u32;
typedef unsigned long long u64;
#endif /* CLIB_AVOID_CLASH_WITH_LINUX_TYPES */

#elif defined(alpha) || (defined(_mips) && __mips == 64) ||                   \
  defined(__x86_64__) || defined(__powerpc64__) || defined(__aarch64__) ||    \
  (defined(__riscv) && __riscv_xlen == 64)
typedef signed int i32;
typedef signed long i64;

#define log2_uword_bits 6
#if defined(_mips)
#define clib_address_bits _MIPS_SZPTR
#else
#define clib_address_bits 64
#endif

#ifndef CLIB_AVOID_CLASH_WITH_LINUX_TYPES
typedef unsigned int u32;
typedef unsigned long u64;
#endif /* CLIB_AVOID_CLASH_WITH_LINUX_TYPES */

#else
#error "can't define types"
#endif

/* Default to 32 bit machines with 32 bit addresses. */
#ifndef log2_uword_bits
#define log2_uword_bits 5
#endif

/* #ifdef's above define log2_uword_bits. */
#define uword_bits (1 << log2_uword_bits)

#ifndef clib_address_bits
#define clib_address_bits 32
#endif

/* Word types. */
#if uword_bits == 64
/* 64 bit word machines. */
typedef i64 word;
typedef u64 uword;
#else
/* 32 bit word machines. */
typedef i32 word;
typedef u32 uword;
#endif

/* integral type of a pointer (used to cast pointers). */
#if clib_address_bits == 64
typedef u64 clib_address_t;
#else
typedef u32 clib_address_t;
#endif

/* These are needed to convert between pointers and machine words.
   MIPS is currently the only machine that can have different sized
   pointers and machine words (but only when compiling with 64 bit
   registers and 32 bit pointers). */
static inline __attribute__((always_inline)) uword
pointer_to_uword(const void *p)
{
	return (uword) (clib_address_t) p;
}

static inline __attribute__((always_inline)) uword
pointer_is_aligned(void *p, uword align)
{
	if ((pointer_to_uword(p) & (align - 1)) == 0)
		return 1;
	return 0;
}

#define uword_to_pointer(u,type) ((type) (clib_address_t) (u))

#endif /* included_clib_types_h */
