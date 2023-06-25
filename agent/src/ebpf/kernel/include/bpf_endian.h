/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef DF_BPF_ENDIAN
#define DF_BPF_ENDIAN

#include "utils.h"

#if (__BYTE_ORDER__) == ( __ORDER_LITTLE_ENDIAN__)
#define ARCH_IS_BIG_ENDIAN	0
#define ARCH_IS_LITTLE_ENDIAN	1
#else
#define ARCH_IS_BIG_ENDIAN	1
#define ARCH_IS_LITTLE_ENDIAN 	0
#endif

#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b-(n+1)*8) >> (b-8) << (m*8))

// TODO: Consider the differences between architectures. 

static __inline __u16 __byte_swap_u16(__u16 x)
{
	if (__builtin_constant_p(x)) {
		return ((__u16) (___bpf_mvb(x, 16, 0, 1) |
				 ___bpf_mvb(x, 16, 1, 0)));
	} else {
		if (ARCH_IS_LITTLE_ENDIAN) {
			return __builtin_bswap16(x);
		} else {
			return x;
		}
	}
}

static __inline __u32 __byte_swap_u32(__u32 x)
{
	if (__builtin_constant_p(x)) {
		return ((__u32) (___bpf_mvb(x, 32, 0, 3) |
				 ___bpf_mvb(x, 32, 1, 2) |
				 ___bpf_mvb(x, 32, 2, 1) |
				 ___bpf_mvb(x, 32, 3, 0)));
	} else {
		if (ARCH_IS_LITTLE_ENDIAN) {
			return __builtin_bswap32(x);
		} else {
			return x;
		}
	}
}

#define __bpf_ntohs(x)  __byte_swap_u16(x)
#define __bpf_htons(x)  __byte_swap_u16(x)
#define __bpf_ntohl(x)  __byte_swap_u32(x)
#define __bpf_htonl(x)  __byte_swap_u32(x)

#endif /* DF_BPF_ENDIAN */
