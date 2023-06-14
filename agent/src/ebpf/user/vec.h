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

#ifndef included_vec_h
#define included_vec_h

#include "string.h"

#define VEC_OK (0)
#define VEC_MEM_ERR (-1)

/* Local variable naming macro (prevents collisions with other macro naming). */
#define _v(var) _vec_##var

/** \brief vector header structure

   Bookkeeping header preceding vector elements in memory.
   User header information may preceed standard vec header.
   If you change u32 len -> u64 len, single vectors can
   exceed 2**32 elements. Clib heaps are vectors. */

typedef struct {
	u32 m_size; /** vec memory size */
	u32 len; /**< Number of elements in vector (NOT its allocated length). */
	u8 hdr_size;  /**< header size divided by VEC_MIN_ALIGN */
	u8 log2_align; /**< data alignment */
	/* 
	 * The meaning of grow_elts is the number of elements
	 * that the vector can grow without reallocating memory.
	 * In other words, when the vector has already allocated
	 * a certain amount of memory, but needs to add more elements,
	 * increasing the value of grow_elts can avoid reallocating
	 * memory and improve program efficiency.
	 */
	u8 grow_elts;  /**< number of elts vector can grow without realloc */
	u8 vpad[5];    /**< pad to 16 bytes */
	u8 vector_data[0]; /**< Vector data . */
} vec_header_t;

#define VEC_MIN_ALIGN 8

/** \brief Find the vector header

    Given the user's pointer to a vector, find the corresponding
    vector header

    @param v pointer to a vector
    @return pointer to the vector's vector_header_t
*/
#define _vec_find(v)	((vec_header_t *) (v) - 1)

static_always_inline u32 __vec_len(void *v)
{
	return _vec_find(v)->len;
}

#define _vec_len(v)	__vec_len ((void *) (v))
#define vec_len(v)	((v) ? _vec_len(v) : 0)

/** \brief Low-level (re)allocation function, usually not called directly

    @param v pointer to a vector
    @param n_elts requested number of elements
    @param elt_sz requested size of one element
    @param hdr_sz header size in bytes (may be zero)
    @param align alignment (may be zero)
    @return v_prime pointer to resized vector, may or may not equal v
*/

typedef struct {
	u32 elt_sz;
	u16 hdr_sz;
	u16 align;
} vec_attr_t;

/* function used t o catch cases where vec_* macros on used on void * */
static_always_inline uword __vec_elt_sz(uword elt_sz, int is_void)
{
	/* vector macro operations on void * are not allowed */
	ASSERT(is_void == 0);
	return elt_sz;
}

#define _vec_is_void(P)                                                       \
  __builtin_types_compatible_p (__typeof__ ((P)[0]), void)
#define _vec_elt_sz(V)   __vec_elt_sz (sizeof ((V)[0]), _vec_is_void (V))

/*
 * ------------------ v - vec_get_header_size(v)
 *
 * vec_header_t
 * (len: _vec_find (v)->hdr_size * VEC_MIN_ALIGN)
 * 
 * ------------------ v
 *
 */
static_always_inline uword vec_get_header_size(void *v)
{
	uword header_size = _vec_find(v)->hdr_size * VEC_MIN_ALIGN;
	return header_size;
}

uword vec_mem_size(void *v);
void *_vec_alloc_internal(uword n_elts, const vec_attr_t * const attr);
void *_vec_realloc_internal(void *v, uword n_elts,
			    const vec_attr_t * const attr);
void *_vec_resize_internal(void *v, uword n_elts,
			   const vec_attr_t * const attr);

/** \brief Number of data bytes in vector. */
#define vec_bytes(v) (vec_len (v) * sizeof (v[0]))

/**
 * Number of elements that can fit into generic vector
 *
 * @param v vector
 * @param b extra header bytes
 * @return number of elements that can fit into vector
 */
always_inline uword vec_max_bytes(void *v)
{
	return v ? vec_mem_size(v) - vec_get_header_size(v) : 0;
}

always_inline uword _vec_max_len(void *v, uword elt_sz)
{
	return vec_max_bytes(v) / elt_sz;
}

#define vec_max_len(v) _vec_max_len (v, _vec_elt_sz (v))

always_inline uword vec_get_align(void *v)
{
	return 1ULL << _vec_find(v)->log2_align;
}

/** \brief Make sure vector is long enough for given index
    and initialize empty space (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @param R alignment status
    @return V (value-result macro parameter)
*/

#define vec_validate_init_empty(V,I,INIT,R) \
  vec_validate_init_empty_ha(V,I,INIT,0,0,R)

static_always_inline void _vec_set_grow_elts(void *v, uword n_elts)
{
	// max : 0xff
	uword max = pow2_mask(BITS(_vec_find(0)->grow_elts));

	if (PREDICT_FALSE(n_elts > max))
		n_elts = max;

	_vec_find(v)->grow_elts = n_elts;
}

always_inline void _vec_set_len(void *v, uword len, uword elt_sz)
{
	ASSERT(v);
	ASSERT(len <= _vec_max_len(v, elt_sz));
	uword old_len = _vec_len(v);
	uword grow_elts = _vec_find(v)->grow_elts;

	if (len > old_len)
		clib_mem_unpoison(v + old_len * elt_sz,
				  (len - old_len) * elt_sz);
	else if (len < old_len)
		clib_mem_poison(v + len * elt_sz, (old_len - len) * elt_sz);

	_vec_set_grow_elts(v, old_len + grow_elts - len);
	_vec_find(v)->len = len;
}

#define vec_set_len(v, l) _vec_set_len ((void *) v, l, _vec_elt_sz (v))

static_always_inline void _vec_update_pointer(void **vp, void *v)
{
	/* avoid store if not needed */
	if (v != vp[0])
		vp[0] = v;
}

/** \brief Resize a vector (general version).
   Add N elements to end of given vector V, return pointer to start of vector.
   Vector will have room for H header bytes and will have user's data aligned
   at alignment A (rounded to next power of 2).

    @param V pointer to a vector
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @param R alignment status
    @return V (value-result macro parameter)
*/
static_always_inline void
_vec_resize(void **vp, uword n_add, uword hdr_sz, uword align, uword elt_sz,
	    int *r)
{
	void *v = *vp;
	if (PREDICT_FALSE(v == 0)) {
		const vec_attr_t va = {.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = hdr_sz
		};
		*vp = _vec_alloc_internal(n_add, &va);
		if (*vp == NULL)
			*r = VEC_MEM_ERR;
		else
			*r = VEC_OK;
		return;
	}

	if (PREDICT_FALSE(_vec_find(v)->grow_elts < n_add)) {
		const vec_attr_t va = {.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = hdr_sz
		};
		v = _vec_resize_internal(v, _vec_len(v) + n_add, &va);
		if (v == NULL) {
			*r = VEC_MEM_ERR;
			return;
		}
		_vec_update_pointer(vp, v);
	} else {
		_vec_set_len(v, _vec_len(v) + n_add, elt_sz);
	}

	*r = VEC_OK;
}

/* calculate minimum alignment out of data natural alignment and provided
 * value, should not be < VEC_MIN_ALIGN */
static_always_inline uword
__vec_align(uword data_align, uword configuered_align)
{
	data_align = clib_max(data_align, configuered_align);
	ASSERT(count_set_bits(data_align) == 1);
	return clib_max(VEC_MIN_ALIGN, data_align);
}

#define _vec_align(V, A) __vec_align (__alignof__((V)[0]), A)

#define vec_resize_ha(V, N, H, A, R)                                             \
  _vec_resize ((void **) &(V), N, H, _vec_align (V, A), _vec_elt_sz (V), (int *) &(R))

/** \brief Find a user vector header
 *
 *  Finds the user header of a vector with unspecified alignment given
 *  the user pointer to the vector.
 */
always_inline void *vec_header(void *v)
{
	return v ? v - vec_get_header_size(v) : 0;
}

/** \brief Free vector's memory (no header).
    @param V pointer to a vector
    @return V (value-result parameter, V=0)
*/

static_always_inline void _vec_free(void **vp)
{
	if (vp[0] == 0)
		return;
	clib_mem_free(vec_header(vp[0]));
	vp[0] = 0;
}

#define vec_free(V) _vec_free ((void **) &(V))

/** \brief Make sure vector is long enough for given index
    and initialize empty space (general version)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @param R alignment status
    @return V (value-result macro parameter)
*/
#define vec_validate_init_empty_ha(V, I, INIT, H, A, R)                       \
  do {                                                                        \
    word _v (i) = (I);                                                        \
    word _v (l) = vec_len (V);                                                \
    if (_v (i) >= _v (l)) {                                                   \
       vec_resize_ha (V, 1 + (_v (i) - _v (l)), H, A, R);                     \
       while (_v (l) <= _v (i) && (R) == VEC_OK) {                            \
           (V)[_v (l)] = (INIT);                                              \
           _v (l)++;                                                          \
       }                                                                      \
    }                                                                         \
  } while (0)

/** \brief Delete N elements starting at element M

    @param V pointer to a vector
    @param N number of elements to delete
    @param M first element to delete
    @return V (value-result macro parameter)
*/

static_always_inline void
_vec_delete(void *v, uword n_del, uword first, uword elt_sz)
{
	word n_bytes_del, n_bytes_to_move, len = vec_len(v);
	u8 *dst;

	if (n_del == 0)
		return;

	ASSERT(first + n_del <= len);

	n_bytes_del = n_del * elt_sz;
	n_bytes_to_move = (len - first - n_del) * elt_sz;
	dst = v + first * elt_sz;

	if (n_bytes_to_move > 0)
		clib_memmove(dst, dst + n_bytes_del, n_bytes_to_move);
	clib_memset(dst + n_bytes_to_move, 0, n_bytes_del);

	_vec_set_len(v, _vec_len(v) - n_del, elt_sz);
}

#define vec_delete(V, N, M) _vec_delete ((void *) (V), N, M, _vec_elt_sz (V))

/** \brief Make sure vector is long enough for given index (general version).

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

always_inline void
_vec_zero_elts(void *v, uword first, uword count, uword elt_sz)
{
	memset(v + (first * elt_sz), 0, count * elt_sz);
}

#define vec_zero_elts(V, F, C) _vec_zero_elts (V, F, C, sizeof ((V)[0]))

static_always_inline void
_vec_validate(void **vp, uword index, uword header_size, uword align,
	      void *heap, uword elt_sz, int *r)
{
	void *v = *vp;
	uword vl, n_elts = index + 1;

	if (PREDICT_FALSE(v == 0)) {
		const vec_attr_t va = {
			.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = header_size
		};
		*vp = _vec_alloc_internal(n_elts, &va);
		if (*vp == NULL)
			*r = VEC_MEM_ERR;
		else
			*r = VEC_OK;
		return;
	}

	vl = _vec_len(v);

	if (PREDICT_FALSE(index < vl)) {
		*r = VEC_OK;
		return;
	}

	if (PREDICT_FALSE(index >= _vec_find(v)->grow_elts + vl)) {
		const vec_attr_t va = {.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = header_size
		};
		v = _vec_resize_internal(v, n_elts, &va);
		if (v == NULL) {
			*r = VEC_MEM_ERR;
			return;
		}
		_vec_update_pointer(vp, v);
	} else
		_vec_set_len(v, n_elts, elt_sz);

	_vec_zero_elts(v, vl, n_elts - vl, elt_sz);

	*r = VEC_OK;
}

#define vec_validate_hap(V, I, H, A, P, R)                                       	\
  _vec_validate ((void **) &(V), I, H, _vec_align (V, A), 0, sizeof ((V)[0]), (int *)&(R))

/** \brief Make sure vector is long enough for given index
    (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param R alignment status
    @return V (value-result macro parameter)
*/
#define vec_validate(V, I, R) vec_validate_hap (V, I, 0, 0, 0, R)

/** \brief End (last data address) of vector. */
#define vec_end(v)	((v) + vec_len (v))

/** \brief Vector iterator */
#define vec_foreach(var,vec) for (var = (vec); var < vec_end (vec); var++)

/** \brief Add 1 element to end of vector (general version).

    @param V pointer to a vector
    @param E element to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @param R return valude (Indicate whether there is an error)
    @return V (value-result macro parameter)
*/

static_always_inline void *_vec_add1(void **vp, uword hdr_sz, uword align,
				     uword elt_sz)
{
	void *v = vp[0];
	uword len;

	if (PREDICT_FALSE(v == 0)) {
		const vec_attr_t va = {.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = hdr_sz
		};
		return *vp = _vec_alloc_internal(1, &va);
	}

	len = _vec_len(v);

	if (PREDICT_FALSE(_vec_find(v)->grow_elts == 0)) {
		const vec_attr_t va = {.elt_sz = elt_sz,
			.align = align,
			.hdr_sz = hdr_sz
		};
		v = _vec_resize_internal(v, len + 1, &va);
		if (v == NULL)
			return NULL;
		_vec_update_pointer(vp, v);
	} else
		_vec_set_len(v, len + 1, elt_sz);

	return v + len * elt_sz;
}

#define vec_add1_ha(V, E, H, A, R)							\
do {											\
    __typeof__ ((V)[0]) * _v(tmp);							\
    _v(tmp) = _vec_add1 ((void **) &(V), H, _vec_align (V, A), _vec_elt_sz (V));	\
    if (_v(tmp) == NULL)								\
         R = VEC_MEM_ERR;								\
    else										\
	 _v(tmp)[0] = (E);								\
} while (0)

/** \brief Add 1 element to end of vector (unspecified alignment).

    @param V pointer to a vector
    @param E element to add
    @param R return value (Indicate whether there is an error)
    @return V (value-result macro parameter)
*/
#define vec_add1(V,E,R)           vec_add1_ha(V,E,0,0,R)
#endif /* included_vec_h */
