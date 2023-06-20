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

#include <string.h> // memset()
#include "types.h"
#include "clib.h"
#include "mem.h"
#include "log.h"
#include "string.h"
#include "vec.h"

uword vec_mem_size(void *v)
{
	return v ? _vec_find(v)->m_size : 0;
}

static inline void
_vec_update_len(void *v, uword n_elts, uword elt_sz, uword n_data_bytes,
		uword unused_bytes)
{
	_vec_find(v)->len = n_elts;
	_vec_set_grow_elts(v, unused_bytes / elt_sz);
	clib_mem_unpoison(v, n_data_bytes);
	clib_mem_poison(v + n_data_bytes, unused_bytes);
}

void *_vec_realloc_internal(void *v, uword n_elts,
			    const vec_attr_t * const attr)
{
	uword old_alloc_sz, new_alloc_sz, new_data_size, n_data_bytes,
	    data_offset;
	uword elt_sz;

	if (PREDICT_FALSE(v == 0))
		return _vec_alloc_internal(n_elts, attr);

	elt_sz = attr->elt_sz;
	/* new elts size */
	n_data_bytes = n_elts * elt_sz;
	/* header size */
	data_offset = vec_get_header_size(v);
	/* new size */
	new_data_size = data_offset + n_data_bytes;

	new_alloc_sz = old_alloc_sz = _vec_find(v)->m_size;

	/* realloc if new size cannot fit into existing allocation */
	if (old_alloc_sz < new_data_size) {
		uword n_bytes, req_size = new_data_size;
		void *p = v - data_offset;
		/* To avoid the inefficiency caused by multiple requests
		 * for memory, we will allocate extra elts as redundancy.*/
		req_size += n_data_bytes / 2;

		p = clib_mem_realloc_aligned("vec_realloc", p, req_size, vec_get_align(v),
					     &new_alloc_sz);
		if (p == NULL) {
			ebpf_warning("_vec_realloc_internal realloc error.\n");
			return NULL;
		}

		v = p + data_offset;
		_vec_find(v)->m_size = new_alloc_sz;

		/* zero out new allocation */
		n_bytes = new_alloc_sz - old_alloc_sz;
		memset(p + old_alloc_sz, 0, n_bytes);
	}

	_vec_update_len(v, n_elts, elt_sz, n_data_bytes,
			new_alloc_sz - new_data_size);
	return v;
}

void *_vec_resize_internal(void *v, uword n_elts, const vec_attr_t * const attr)
{
	uword elt_sz = attr->elt_sz;
	if (PREDICT_TRUE(v != 0)) {
		uword hs = _vec_find(v)->hdr_size * VEC_MIN_ALIGN;
		uword alloc_sz = vec_mem_size(v);
		uword n_data_bytes = elt_sz * n_elts;
		word unused_bytes = alloc_sz - (n_data_bytes + hs);

		if (PREDICT_TRUE(unused_bytes >= 0)) {
			_vec_update_len(v, n_elts, elt_sz, n_data_bytes,
					unused_bytes);
			return v;
		}
	}

	/*
	 * this shouled emit tail jump and likely avoid stack usasge inside this
	 * function
	 */
	return _vec_realloc_internal(v, n_elts, attr);
}

void *_vec_alloc_internal(uword n_elts, const vec_attr_t * const attr)
{
	uword req_size, alloc_size, data_offset, align;
	uword elt_sz = attr->elt_sz;
	void *p, *v;

	/* alignment must be power of 2 */
	align = clib_max(attr->align, VEC_MIN_ALIGN);
	ASSERT(count_set_bits(align) == 1);

	/* calc offset where vector data starts */
	data_offset = attr->hdr_sz + sizeof(vec_header_t);
	data_offset = round_pow2(data_offset, align);

	req_size = data_offset + n_elts * elt_sz;
	p = clib_mem_alloc_aligned("vec_alloc", req_size, align, &alloc_size);
	if (p == NULL) {
		ebpf_warning("mem_alloc_aligned failed.\n");
		return NULL;
	}

	/* zero out whole alocation */
	clib_mem_unpoison(p, alloc_size);
	memset(p, 0, alloc_size);

	/* fill vector header */
	v = p + data_offset;
	_vec_find(v)->len = n_elts;
	_vec_find(v)->hdr_size = data_offset / VEC_MIN_ALIGN;
	_vec_find(v)->log2_align = min_log2(align);
	_vec_find(v)->m_size = alloc_size;

	/* poison extra space given by allocator */
	clib_mem_poison(p + req_size, alloc_size - req_size);
	_vec_set_grow_elts(v, (alloc_size - req_size) / elt_sz);
	return v;
}
