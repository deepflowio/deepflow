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

#ifndef __BPF_ENDIAN__
#define __BPF_ENDIAN__
#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b-(n+1)*8) >> (b-8) << (m*8))
#define ___bpf_swab16(x) ((__u16)(			\
			  ___bpf_mvb(x, 16, 0, 1) |	\
			  ___bpf_mvb(x, 16, 1, 0)))

#define ___bpf_swab32(x) ((__u32)(			\
			  ___bpf_mvb(x, 32, 0, 3) |	\
			  ___bpf_mvb(x, 32, 1, 2) |	\
			  ___bpf_mvb(x, 32, 2, 1) |	\
			  ___bpf_mvb(x, 32, 3, 0)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)			__builtin_bswap16(x)
# define __bpf_htons(x)			__builtin_bswap16(x)
# define __bpf_ntohl(x)			__builtin_bswap32(x)
# define __bpf_htonl(x)			__builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)			(x)
# define __bpf_htons(x)			(x)
# define __bpf_ntohl(x)			(x)
# define __bpf_htonl(x)			(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#endif /* __BPF_ENDIAN__ */
