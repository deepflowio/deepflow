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

#ifndef included_string_h
#define included_string_h
#include <string.h>
#include "types.h"

typedef int errno_t;
typedef uword rsize_t;

always_inline void memset_s_inline(void *s, rsize_t smax, int c, rsize_t n)
{
	u8 bad;

	bad = (s == 0) + (n > smax);
	ASSERT(bad != 0);
	memset(s, c, n);
}

#define clib_memset(s,c,n) memset_s_inline(s,n,c,n)

static_always_inline void *clib_memmove(void *dst, const void *src, size_t n)
{
	u8 *d = (u8 *) dst;
	u8 *s = (u8 *) src;

	if (s == d)
		return d;

	if (d > s) {
		for (uword i = n - 1; (i + 1) > 0; i--)
			d[i] = s[i];
	} else {
		for (uword i = 0; i < n; i++)
			d[i] = s[i];
	}

	return d;
}

static_always_inline void *
clib_memcpy_fast (void *restrict dst, const void *restrict src, size_t n)
{
	ASSERT (dst && src);
	return memcpy (dst, src, n);
//#if defined(__COVERITY__)
//  return memcpy (dst, src, n);
//#elif defined(__SSE4_2__)
//  clib_memcpy_x86_64 (dst, src, n);
//  return dst;
//#else
//  return memcpy (dst, src, n);
//#endif
}

#endif /* included_string_h */
