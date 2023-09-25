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
  Copyright (c) 2006 Eliot Dresselhaus

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

static_always_inline void *clib_memcpy_fast(void *restrict dst,
					    const void *restrict src, size_t n)
{
	ASSERT(dst && src);
	return memcpy(dst, src, n);
//#if defined(__COVERITY__)
//  return memcpy (dst, src, n);
//#elif defined(__SSE4_2__)
//  clib_memcpy_x86_64 (dst, src, n);
//  return dst;
//#else
//  return memcpy (dst, src, n);
//#endif
}

/**
 * @brief copy src to dest, at most n bytes, up to dmax
 *
 *        ISO/IEC 9899:2017(C11), Porgramming languages -- C
 *        Annex K; Bounds-checking interfaces
 *
 * @param *dest  pointer to memory to copy to
 * @param dmax   maximum length of resulting dest
 * @param *src   pointer to memory to copy from
 * @param n      maximum number of characters to copy from src
 *
 * @constraints  No null pointers
 *               n shall not be greater than dmax
 *               no memory overlap between src and dest
 *
 * @return EOK        success
 *         EINVAL     runtime constraint error
 *
 */
always_inline errno_t
memcpy_s_inline(void *__restrict__ dest, rsize_t dmax,
		const void *__restrict__ src, rsize_t n)
{
	uword low, hi;
	u8 bad;

	/*
	 * Optimize constant-number-of-bytes calls without asking
	 * "too many questions for someone from New Jersey"
	 */
	if (COMPILE_TIME_CONST(n)) {
		clib_memcpy_fast(dest, src, n);
		return 0;
	}

	/*
	 * call bogus if: src or dst NULL, trying to copy
	 * more data than we have space in dst, or src == dst.
	 * n == 0 isn't really "bad", so check first in the
	 * "wall-of-shame" department...
	 */
	bad = (dest == 0) + (src == 0) + (n > dmax) + (dest == src) + (n == 0);
	if (PREDICT_FALSE(bad != 0)) {
		/* Not actually trying to copy anything is OK */
		if (n == 0)
			return 0;
		if (dest == NULL)
			ebpf_error("dest NULL");
		if (src == NULL)
			ebpf_error("src NULL");
		if (n > dmax)
			ebpf_error("n > dmax");
		if (dest == src)
			ebpf_error("dest == src");
		return -1;
	}

	/* Check for src/dst overlap, which is not allowed */
	low = (uword) (src < dest ? src : dest);
	hi = (uword) (src < dest ? dest : src);

	if (PREDICT_FALSE(low + (n - 1) >= hi)) {
		ebpf_error("src/dest overlap");
		return -1;
	}

	clib_memcpy_fast(dest, src, n);
	return 0;
}

always_inline errno_t
strcpy_s_inline(void *__restrict__ dest, rsize_t dmax,
		const void *__restrict__ src, rsize_t n)
{
	errno_t err;

	if (n > dmax)
		n = dmax;

	err = memcpy_s_inline(dest, dmax, src, n);
	if (err == 0) {
		rsize_t no_use_n = dmax - n;
		if (no_use_n > 0) {
			memset(dest + n, 0, no_use_n);
		} else {
			char *_d = dest;
			_d[dmax - 1] = '\0';
		}
	}

	return err;
}

#endif /* included_string_h */
