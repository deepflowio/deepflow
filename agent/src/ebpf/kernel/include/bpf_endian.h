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
