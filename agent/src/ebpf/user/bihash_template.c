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
  Copyright (c) 2014 Cisco and/or its affiliates.

  * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

// Bounded-index extensible hash

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef BIIHASH_MIN_ALLOC_LOG2_PAGES
#define BIIHASH_MIN_ALLOC_LOG2_PAGES 10
#endif

int BV(clib_bihash_is_initialised) (const BVT(clib_bihash) * h) {
	return (h->instantiated != 0);
}

void BV(clib_bihash_free) (BVT(clib_bihash) * h) {
	if (PREDICT_FALSE(h->instantiated == 0))
		goto never_initialized;

	h->instantiated = 0;

	vec_free(h->working_copies);
	vec_free(h->working_copy_lengths);
	clib_mem_free((void *)h->alloc_lock);
	vec_free(h->freelists);
	clib_mem_vm_free((void *)(uword) (alloc_arena(h)), alloc_arena_size(h));
never_initialized:
	/* hash-header struct not free */
	/* if not add to clib_all_bihashes, return */
	if (h->dont_add_to_all_bihash_list) {
		memset(h, 0, sizeof(*h));
		return;
	}
	memset(h, 0, sizeof(*h));
}

static inline void *BV(alloc_aligned) (BVT(clib_bihash) * h, uint64_t nbytes) {
	uint64_t rv;

	/* Round to an even number of cache lines */
	nbytes = round_pow2(nbytes, CLIB_CACHE_LINE_BYTES);
	rv = alloc_arena_next(h);
	alloc_arena_next(h) += nbytes;
	if (alloc_arena_next(h) > alloc_arena_size(h)) {
		ebpf_warning("The requested memory space exceeds the"
			     "maximum memory reserved by the hash.\n");
		return NULL;
	}

	/* Exceeds the mapped memory */
	if (alloc_arena_next(h) > alloc_arena_mapped(h)) {
		void *base, *rv;
		uint64_t alloc = alloc_arena_next(h) - alloc_arena_mapped(h);
		int mmap_flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
		/* MAP_HUGETLB need CAP_SYS_RESOURCE */
		int mmap_flags_huge = (mmap_flags | MAP_HUGETLB | MAP_LOCKED |
				       BIHASH_LOG2_HUGEPAGE_SIZE <<
				       MAP_HUGE_SHIFT);

		/* new allocation is 25% of existing one */
		if (alloc_arena_mapped(h) >> 2 > alloc)
			alloc = alloc_arena_mapped(h) >> 2;

		/* round allocation to page size */
		alloc = round_pow2(alloc, 1 << BIHASH_LOG2_HUGEPAGE_SIZE);

		base =
		    (void *)(uint64_t) (alloc_arena(h) + alloc_arena_mapped(h));

		rv = mmap(base, alloc, PROT_READ | PROT_WRITE, mmap_flags_huge,
			  -1, 0);

		/*
		 * fallback - maybe we are still able to allocate normal pages
		 * mlock() need root or CAP_IPC_LOCK
		 */
		if (rv == MAP_FAILED || mlock(base, alloc) != 0)
			rv = mmap(base, alloc, PROT_READ | PROT_WRITE,
				  mmap_flags, -1, 0);

		if (rv == MAP_FAILED) {
			ebpf_warning("mmap() failed - %s (%d)", strerror(errno),
				     errno);
			return NULL;
		}

		alloc_arena_mapped(h) += alloc;
	}

	return (void *)(uint64_t) (rv + alloc_arena(h));
}

/*
 * The bucket-value used by bucket is allocated from the hash
 * alloc_arena(h) memory, and the bucket offset value records
 * the distance from alloc_arena(h). Memory is first allocated
 * by searching h->freelists[log2_page]. If it is not found here,
 * it is allocated from alloc_arena(h).
 * 
 *            page | kv - pair |
 *            |    | ----------|
 *            |    | kv - pair |
 *            |    | ----------|
 *            |    | ... ...   |
 * log2_page  ---- =============
 *            page | kv - pair |
 *            |    |-----------|
 *            |     ... ...
 *            ...
 * log2_page represents the exponent of the number of pages
 * (i.e. the number of pages is 1 << log2_page), and each page
 * contains IHASH_KVP_PER_PAGE kv-pairs. The size of the storage
 * in the bucket is expandable. 
 */
static
BVT(clib_bihash_value) * BV(value_alloc) (BVT(clib_bihash) * h, u32 log2_pages)
{
	/*
	 * union {
	 *   BVT(clib_bihash_kv) kvp[BIHASH_KVP_PER_PAGE];
	 *   u64 next_free_as_u64;
	 * };
	 */
	int i;
	BVT(clib_bihash_value) * rv = 0;

	/* 
	 * This function must be executed under lock protection, here used
	 * to check and ensure that the lock has been acquired.
	 * (pre call BV(clib_bihash_alloc_lock) (h))
	 */
	ASSERT(h->alloc_lock[0]);

	/* log2_pages is h->freelists index */
	if (log2_pages >= vec_len(h->freelists)
	    || h->freelists[log2_pages] == 0) {
		/* h->freelists[log2_pages] record offset from mmap base address,
		 * vm has requested, h->freelists setting of 0 */
		int ret = VEC_OK;
		vec_validate_init_empty(h->freelists, log2_pages, 0, ret);
		if (ret != VEC_OK) {
			ebpf_warning("vec_validate_init_empty() failed, "
				     "log2_pages %d, ret %d\n",
				     log2_pages, ret);
			return NULL;
		}
		/* map fixed vm */
		rv = BV(alloc_aligned) (h, (sizeof(*rv) * (1 << log2_pages)));
		if (rv == NULL)
			return rv;

		goto initialize;
	}

	rv = BV(clib_bihash_get_value) (h, (uword) h->freelists[log2_pages]);
	h->freelists[log2_pages] = rv->next_free_as_u64;

initialize:
	ASSERT(rv);

	BVT(clib_bihash_kv) * v;
	v = (BVT(clib_bihash_kv) *) rv;	// one bucket kv-pair strat address

	for (i = 0; i < BIHASH_KVP_PER_PAGE * (1 << log2_pages); i++) {
		BV(clib_bihash_mark_free) (v);
		v++;
	}

	return rv;
}

static void
BV(value_free) (BVT(clib_bihash) * h, BVT(clib_bihash_value) * v,
		u32 log2_pages) {
	ASSERT(h->alloc_lock[0]);

	ASSERT(vec_len(h->freelists) > log2_pages);

	//if (CLIB_DEBUG > 0)
	//      memset(v, 0xFE, sizeof (*v) * (1 << log2_pages));

	v->next_free_as_u64 = (u64) h->freelists[log2_pages];
	h->freelists[log2_pages] = (u64) BV(clib_bihash_get_offset) (h, v);
}

static inline int
BV(make_working_copy) (BVT(clib_bihash) * h, BVT(clib_bihash_bucket) * b) {
	BVT(clib_bihash_value) * v;
	BVT(clib_bihash_bucket) working_bucket __attribute__((aligned(8)));
	BVT(clib_bihash_value) * working_copy;
	int log2_working_copy_length;

	ASSERT(h->alloc_lock[0]);

	if (thread_index >= vec_len(h->working_copies)) {
		int ret = VEC_OK;
		vec_validate(h->working_copies, thread_index, ret);
		if (ret != VEC_OK) {
			ebpf_warning("vec_validate h->working_copies failed, "
				     "thread_index : %d, ret %d\n",
				     thread_index, ret);
			return (-1);
		}
		ret = VEC_OK;
		vec_validate_init_empty(h->working_copy_lengths, thread_index,
					~0, ret);
		if (ret != VEC_OK) {
			ebpf_warning
			    ("vec_validate h-working_copy_lengths failed, thread_index : %d\n",
			     thread_index);
			return (-1);
		}
	}

	/*
	 * working_copies are per-cpu so that near-simultaneous
	 * updates from multiple threads will not result in sporadic, spurious
	 * lookup failures.
	 */
	working_copy = h->working_copies[thread_index];
	log2_working_copy_length = h->working_copy_lengths[thread_index];

	h->saved_bucket.as_u64 = b->as_u64;

	if (b->log2_pages > log2_working_copy_length) {
		/*
		 * It's not worth the bookkeeping to free working copies
		 *   if (working_copy)
		 *     clib_clib_mem_free (working_copy);
		 */
		working_copy = BV(alloc_aligned)
		    (h, sizeof(working_copy[0]) * (1 << b->log2_pages));
		if (working_copy == NULL) {
			ebpf_warning("working_copy alloc_aligned() failed.\n");
			return (-1);
		}
		h->working_copy_lengths[thread_index] = b->log2_pages;
		h->working_copies[thread_index] = working_copy;
		__sync_fetch_and_add(&h->working_copy_lost_stat,
				     1ULL << b->log2_pages);
	}

	v = BV(clib_bihash_get_value) (h, b->offset);

	clib_memcpy_fast(working_copy, v, sizeof(*v) * (1 << b->log2_pages));
	working_bucket.as_u64 = b->as_u64;
	working_bucket.offset = BV(clib_bihash_get_offset) (h, working_copy);
	CLIB_MEMORY_STORE_BARRIER();
	b->as_u64 = working_bucket.as_u64;	/* Different threads enter their
						   respective working_copy. */
	h->working_copies[thread_index] = working_copy;
	return (0);
}

/*
 * Traverse all old clib_bihash_value, rehash all kv-pair data in the
 * old bihash_value, and fill them into the new clib_bihash_value.
 */
/* *INDENT-OFF* */
static BVT(clib_bihash_value) * BV(split_and_rehash)
				(BVT(clib_bihash) * h,
				 BVT(clib_bihash_value) * old_values,
				 u32 old_log2_pages,
				 u32 new_log2_pages)
/* *INDENT-ON* */

{
	BVT(clib_bihash_value) * new_values, *new_v;
	int i, j, length_in_kvs;

	ASSERT(h->alloc_lock[0]);

	new_values = BV(value_alloc) (h, new_log2_pages);
	length_in_kvs = (1 << old_log2_pages) * BIHASH_KVP_PER_PAGE;

	for (i = 0; i < length_in_kvs; i++) {
		u64 new_hash;

		/* Entry not in use? Forget it */
		if (BV(clib_bihash_is_free) (&(old_values->kvp[i])))
			continue;

		/* rehash the item onto its new home-page
		 * clib_bihash_hash() is clib_bihash_hash_xx_x() */
		new_hash = BV(clib_bihash_hash) (&(old_values->kvp[i]));
		new_hash =
		    extract_bits(new_hash, h->log2_nbuckets, new_log2_pages);
		new_v = &new_values[new_hash];

		/* Across the new home-page */
		for (j = 0; j < BIHASH_KVP_PER_PAGE; j++) {
			/* Empty slot */
			if (BV(clib_bihash_is_free) (&(new_v->kvp[j]))) {
				clib_memcpy_fast(&(new_v->kvp[j]),
						 &(old_values->kvp[i]),
						 sizeof(new_v->kvp[j]));
				goto doublebreak;
			}
		}
		/* Crap. Tell caller to try again */
		BV(value_free) (h, new_values, new_log2_pages);
		return (0);
	      doublebreak:;
	}

	return new_values;
}

/* *INDENT-OFF* */
static BVT(clib_bihash_value) * BV(split_and_rehash_linear)
				(BVT(clib_bihash) * h,
				 BVT(clib_bihash_value) * old_values,
				 u32 old_log2_pages,
				 u32 new_log2_pages)
/* *INDENT-ON* */

{
	BVT(clib_bihash_value) * new_values;
	int i, j, new_length, old_length;

	ASSERT(h->alloc_lock[0]);

	new_values = BV(value_alloc) (h, new_log2_pages);
	new_length = (1 << new_log2_pages) * BIHASH_KVP_PER_PAGE;
	old_length = (1 << old_log2_pages) * BIHASH_KVP_PER_PAGE;

	j = 0;
	/* Across the old value array */
	for (i = 0; i < old_length; i++) {
		/* Find a free slot in the new linear scan bucket */
		for (; j < new_length; j++) {
			/* Old value not in use? Forget it. */
			if (BV(clib_bihash_is_free) (&(old_values->kvp[i])))
				goto doublebreak;

			/* New value should never be in use */
			if (BV(clib_bihash_is_free) (&(new_values->kvp[j]))) {
				/* Copy the old value and move along */
				clib_memcpy_fast(&(new_values->kvp[j]),
						 &(old_values->kvp[i]),
						 sizeof(new_values->kvp[j]));
				j++;
				goto doublebreak;
			}
		}
		/* This should never happen... */
		ebpf_warning("BUG: linear rehash failed!");
		BV(value_free) (h, new_values, new_log2_pages);
		return (0);

	      doublebreak:;
	}
	return new_values;
}

/*
 * If a bucket is using BIHASH_KVP_AT_BUCKET_LEVEL, then there is a
 * page (log2_page=0, b->refcnt = 1) directly after the bucket header.
 * Each page contains BIHASH_KVP_PER_PAGE kv-pairs, and b->refcnt is
 * initially set to 1. Whenever a kv-pair in the bucket is used,
 * b->refcnt is incremented. When a hash value is used to locate a bucket,
 * kv-pairs are appended to the bucket. If there are no available slots,
 * the bucket needs to be expanded. Expansion involves searching
 * h->freelists[log2_page] and allocating from alloc_arena(h) if necessary.
 * The hash value is used to locate the bucket and page where the kv-pair
 * is located. If expansion is successful, the key-values are rewritten to
 * the new kv-array, and a new slot is obtained. If expansion is unsuccessful,
 * the linear method (split_and_rehash_linear) is used to traverse all slots
 * in the bucket. The process is repeated until a free slot is found for the
 * new kv-pair. If BIHASH_KVP_AT_BUCKET_LEVEL=0, there is no fixed page
 * (with BIHASH_KVP_PER_PAGE kv-pairs) after the bucket header array.
 */
/* *INDENT-OFF* */
static_always_inline int
BV(clib_bihash_add_del_inline_with_hash) (BVT(clib_bihash) * h,
		BVT(clib_bihash_kv) * add_v, u64 hash, int is_add,
		int (*is_stale_cb) (BVT(clib_bihash_kv)*, void *),
		void *is_stale_arg,
		void (*overwrite_cb) (BVT(clib_bihash_kv)*, void *),
		void *overwrite_arg) {
	BVT(clib_bihash_bucket) * b, tmp_b;
	BVT(clib_bihash_value) * v, *new_v, *save_new_v, *working_copy;
	int i, limit;
	u64 new_hash;
	u32 new_log2_pages, old_log2_pages;
	int mark_bucket_linear;
	int resplit_once;

	static const BVT (clib_bihash_bucket) mask = {
		.linear_search = 1,
		.log2_pages = -1
	};

	/* Debug image: make sure the table has been instantiated */
	ASSERT(h->instantiated != 0);

	/*
	 * Debug image: make sure that an item being added doesn't accidentally
	 * look like a free item.
	 * e.g.:clib_bihash_is_free_xxx_xxx_t (clib_bihash_kv_xxx_xxx_t * v)
	 * (item not free)
	 */
	ASSERT((is_add && BV(clib_bihash_is_free) (add_v)) == 0);

	/* get bucket by offset */
	b = BV(clib_bihash_get_bucket) (h, hash);

	BV(clib_bihash_lock_bucket) (b);

	/*
	 * Each bucket in the hash table stores a pointer to the
	 * key-value pair, while the key-value pairs are stored in
	 * separate memory locations.
	 */
	if (BIHASH_KVP_AT_BUCKET_LEVEL == 0
	    && BV(clib_bihash_bucket_is_empty) (b)) {
		if (is_add == 0) {
			/* Bucket is empty, if delete, nothing to do */
			BV(clib_bihash_unlock_bucket) (b);
			return (-1);
		}

		BV(clib_bihash_alloc_lock) (h);
		v = BV(value_alloc) (h, 0);
		BV(clib_bihash_alloc_unlock) (h);

		*v->kvp = *add_v;
		tmp_b.as_u64 = 0;	/* clears bucket lock */
		tmp_b.offset = BV(clib_bihash_get_offset) (h, v);
		tmp_b.refcnt = 1;
		CLIB_MEMORY_STORE_BARRIER();

		b->as_u64 = tmp_b.as_u64;	/* unlocks the bucket */
		__sync_fetch_and_add(&h->add_increment_stat, 1);

		return (0);
	}

	/* WARNING: we're still looking at the live copy... */
	limit = BIHASH_KVP_PER_PAGE;
	v = BV(clib_bihash_get_value) (h, b->offset);

	/* linear_search and log2_pages fetch
	 * bucket
	 * --------
	 *   | page
	 *   ======
	 *   | page
	 *   ======
	 * extract_bits() confirm the offset of the page. 
	 */
	if (PREDICT_FALSE(b->as_u64 & mask.as_u64)) {
		if (PREDICT_FALSE(b->linear_search))
			limit <<= b->log2_pages;
		else
			v += extract_bits(hash, h->log2_nbuckets,
					  b->log2_pages);
	}

	if (is_add) {
		/*
		 * Because reader threads are looking at live data,
		 * we have to be extra careful. Readers do NOT hold the
		 * bucket lock. We need to be SLOWER than a search, past the
		 * point where readers CHECK the bucket lock.
		 */

		/*
		 * For obvious (in hindsight) reasons, see if we're supposed to
		 * replace an existing key, then look for an empty slot.
		 */
		for (i = 0; i < limit; i++) {
			if (BV(clib_bihash_is_free) (&(v->kvp[i])))
				continue;
			if (BV(clib_bihash_key_compare)
			    (v->kvp[i].key, add_v->key)) {
				/* Add but do not overwrite? */
				if (is_add == 2) {
					BV(clib_bihash_unlock_bucket) (b);
					return (-2);
				}
				if (overwrite_cb)
					overwrite_cb(&(v->kvp[i]),
						     overwrite_arg);
				clib_memcpy_fast(&(v->kvp[i].value),
						 &add_v->value,
						 sizeof(add_v->value));
				BV(clib_bihash_unlock_bucket) (b);
				__sync_fetch_and_add(&h->replace_increment_stat, 1);
				return (0);
			}
		}

		/*
		 * Look for an empty slot. If found, use it
		 */
		for (i = 0; i < limit; i++) {
			if (BV(clib_bihash_is_free) (&(v->kvp[i]))) {
				/*
				 * Copy the value first, so that if a reader manages
				 * to match the new key, the value will be right...
				 */
				clib_memcpy_fast(&(v->kvp[i].value),
						 &add_v->value,
						 sizeof(add_v->value));
				CLIB_MEMORY_STORE_BARRIER();	/* Make sure the value has settled
								   (Once the key is set, other threads
								   must read the latest value.) */
				clib_memcpy_fast(&(v->kvp[i]), &add_v->key,
						 sizeof(add_v->key));
				b->refcnt++;
				ASSERT(b->refcnt > 0);
				BV(clib_bihash_unlock_bucket) (b);
				__sync_fetch_and_add(&h->add_increment_stat, 1);
				return (0);
			}
		}

		/* look for stale data to overwrite.
		 * If there are no available ones, we can only replace the outdated ones. */
		if (is_stale_cb) {
			for (i = 0; i < limit; i++) {
				if (is_stale_cb(&(v->kvp[i]), is_stale_arg)) {
					clib_memcpy_fast(&(v->kvp[i]), add_v,
							 sizeof(*add_v));
					CLIB_MEMORY_STORE_BARRIER();
					BV(clib_bihash_unlock_bucket) (b);
					__sync_fetch_and_add(&h->replace_increment_stat, 1);
					return (0);
				}
			}
		}
		/* Out of space in this bucket, split the bucket... */
	} else {		/* delete case */
		for (i = 0; i < limit; i++) {
			/* no sense even looking at this one */
			if (BV(clib_bihash_is_free) (&(v->kvp[i])))
				continue;
			/* Found the key? Kill it... 
			 * v exists within a specific page, as a bucket has
			 * 1 << b->log2_pages pages, with each page containing
			 * BIHASH_KVP_PER_PAGE key-value pairs.
			 */
			if (BV(clib_bihash_key_compare)
			    (v->kvp[i].key, add_v->key)) {
				BV(clib_bihash_mark_free) (&(v->kvp[i]));
				/* Is the bucket empty? */
				if (PREDICT_TRUE(b->refcnt > 1)) {
					b->refcnt--;
					/* Switch back to the bucket-level kvp array?
					 * b->refcnt: kv-pare used count for bucket
					 * if b->refcnt == 1, free the page.
					 * b->log2_pages > 0, indicating the existence of
					 * an extension request. BV(value_free) is placed
					 * in h->freelists[log2_pages], and the bucket is set as empty.
					 * b->refcnt == 1 && b->log2_pages == 0, indicate bucket empty.
					 *
					 * When BIHASH_KVP_AT_BUCKET_LEVEL is set to 1, a block of memory
					 * immediately following the bucket header is used to store
					 * BIHASH_KVP_PER_PAGE kv-pairs. This memory is inherent and will
					 * not be released to the hash's shared memory (alloc_arena), which
					 * is actually managed by freelists. "b->log2_pages > 0" indicates
					 * that this bucket uses the hash's shared memory (alloc_arena).
					 * If b->refcnt == 1, it means that the entire bucket is idle, and
					 * at this point, the currently used shared memory must be returned
					 * to alloc_arena (freelists). Note that BV(clib_bihash_alloc_lock) (h)
					 * must be used to protect this operation, and the original inherent
					 * memory bucket value is enabled.
					 */
					if (BIHASH_KVP_AT_BUCKET_LEVEL
					    && b->refcnt == 1
					    && b->log2_pages > 0) {
						tmp_b.as_u64 = b->as_u64;
						/* bucket value offset */
						b->offset =
						    BV(clib_bihash_get_offset)
						    (h, (void *)(b + 1));
						b->linear_search = 0;
						b->log2_pages = 0;
						/* Clean up the bucket-level kvp array */
						BVT(clib_bihash_kv) * v =
						    (void *)(b + 1);
						int j;
						for (j = 0;
						     j < BIHASH_KVP_PER_PAGE;
						     j++) {
							BV(clib_bihash_mark_free) (v);
							v++;
						}
						CLIB_MEMORY_STORE_BARRIER();
						BV(clib_bihash_unlock_bucket)(b);
						__sync_fetch_and_add(&h->del_increment_stat, 1);
						goto free_backing_store;
					}

					CLIB_MEMORY_STORE_BARRIER();
					BV(clib_bihash_unlock_bucket) (b);
					__sync_fetch_and_add(&h->del_increment_stat, 1);
					return (0);
				} else {	/* yes, free it */
					/* Save old bucket value, need log2_pages to free it */
					tmp_b.as_u64 = b->as_u64;

					/* Kill and unlock the bucket */
					b->as_u64 = 0;

				      free_backing_store:
					/* And free the backing storage */
					BV(clib_bihash_alloc_lock) (h);
					/* Note: v currently points into the middle of the bucket */
					v = BV(clib_bihash_get_value) (h,
								       tmp_b.
								       offset);
					BV(value_free) (h, v, tmp_b.log2_pages);
					BV(clib_bihash_alloc_unlock) (h);
					__sync_fetch_and_add(&h->del_increment_stat, 1);
					return (0);
				}
			}
		}

		/* Not found... */
		BV(clib_bihash_unlock_bucket) (b);
		return (-3);
	}

	/* There are no more vacancies available and expansion is needed.*/
	/* Move readers to a (locked) temp copy of the bucket */
	BV(clib_bihash_alloc_lock) (h);
	if (BV(make_working_copy) (h, b) != 0) {
		/* Not enough memory to use.*/
		return (-4);
	}

	v = BV(clib_bihash_get_value) (h, h->saved_bucket.offset);

	old_log2_pages = h->saved_bucket.log2_pages;
	new_log2_pages = old_log2_pages + 1;
	mark_bucket_linear = 0;
	__sync_fetch_and_add(&h->split_add_increment_stat, 1);
	__sync_fetch_and_add(&h->splits_increment_stat, old_log2_pages);

	working_copy = h->working_copies[thread_index];
	resplit_once = 0;
	__sync_fetch_and_add(&h->splits_increment_stat, 1);

	new_v = BV(split_and_rehash) (h, working_copy, old_log2_pages,
				      new_log2_pages);
	if (new_v == 0) {
	      try_resplit:
		resplit_once = 1;
		new_log2_pages++;
		/* Try re-splitting. If that fails, fall back to linear search */
		new_v = BV(split_and_rehash) (h, working_copy, old_log2_pages,
					      new_log2_pages);
		if (new_v == 0) {
		      mark_linear:
			new_log2_pages--;
			/* pinned collisions, use linear search */
			new_v =
			    BV(split_and_rehash_linear) (h, working_copy,
							 old_log2_pages,
							 new_log2_pages);
			mark_bucket_linear = 1;
			__sync_fetch_and_add(&h->linear_increment_stat, 1);
		}
		__sync_fetch_and_add(&h->resplit_increment_stat, 1);
		__sync_fetch_and_add(&h->splits_increment_stat, old_log2_pages + 1);
	}

	/* Try to add the new entry */
	save_new_v = new_v;
	new_hash = BV(clib_bihash_hash) (add_v);
	limit = BIHASH_KVP_PER_PAGE;
	if (mark_bucket_linear)
		limit <<= new_log2_pages;
	else
		new_v +=
		    extract_bits(new_hash, h->log2_nbuckets, new_log2_pages);

	for (i = 0; i < limit; i++) {
		if (BV(clib_bihash_is_free) (&(new_v->kvp[i]))) {
			clib_memcpy_fast(&(new_v->kvp[i]), add_v,
					 sizeof(*add_v));
			goto expand_ok;
		}
	}

	/* Crap. Try again */
	BV(value_free) (h, save_new_v, new_log2_pages);
	/*
	 * If we've already doubled the size of the bucket once,
	 * fall back to linear search now.
	 */
	if (resplit_once)
		goto mark_linear;
	else
		goto try_resplit;

expand_ok:
	tmp_b.log2_pages = new_log2_pages;
	tmp_b.offset = BV(clib_bihash_get_offset) (h, save_new_v);
	tmp_b.linear_search = mark_bucket_linear;
#if BIHASH_KVP_AT_BUCKET_LEVEL
	/* Compensate for permanent refcount bump at the bucket level */
	if (new_log2_pages > 0)
#endif
		tmp_b.refcnt = h->saved_bucket.refcnt + 1;
	ASSERT(tmp_b.refcnt > 0);
	tmp_b.lock = 0;
	CLIB_MEMORY_STORE_BARRIER();
	b->as_u64 = tmp_b.as_u64;

#if BIHASH_KVP_AT_BUCKET_LEVEL
	if (h->saved_bucket.log2_pages > 0) {
#endif

		/* free the old bucket, except at the bucket level if so configured */
		v = BV(clib_bihash_get_value) (h, h->saved_bucket.offset);
		BV(value_free) (h, v, h->saved_bucket.log2_pages);

#if BIHASH_KVP_AT_BUCKET_LEVEL
	}
#endif

	BV(clib_bihash_alloc_unlock) (h);
	return (0);
}
/* *INDENT-ON* */

static_always_inline int BV(clib_bihash_add_del_inline)
 (BVT(clib_bihash) * h, BVT(clib_bihash_kv) * add_v, int is_add,
  int (*is_stale_cb) (BVT(clib_bihash_kv) *, void *), void *arg) {
	u64 hash = BV(clib_bihash_hash) (add_v);
	return BV(clib_bihash_add_del_inline_with_hash) (h, add_v, hash, is_add,
							 is_stale_cb, arg, 0,
							 0);
}

int BV(clib_bihash_add_del)
 (BVT(clib_bihash) * h, BVT(clib_bihash_kv) * add_v, int is_add) {
	return BV(clib_bihash_add_del_inline) (h, add_v, is_add, 0, 0);
}

int BV(clib_bihash_add_del_with_hash) (BVT(clib_bihash) * h,
				       BVT(clib_bihash_kv) * add_v, u64 hash,
				       int is_add) {
	return BV(clib_bihash_add_del_inline_with_hash) (h, add_v, hash, is_add,
							 0,
							 0, 0, 0);
}

static int BV(clib_bihash_instantiate) (BVT(clib_bihash) * h) {
	uint64_t bucket_size;
	/* Used for the application of clib_bihash_value. */
	alloc_arena(h) =
	    clib_mem_vm_reserve(h->memory_size, BIHASH_LOG2_HUGEPAGE_SIZE);
	if (alloc_arena(h) == ~0) {
		ebpf_warning("Rserve vm space failed.\n");
		return (-1);
	}

	alloc_arena_next(h) = 0;
	alloc_arena_size(h) = h->memory_size;
	alloc_arena_mapped(h) = 0;

	bucket_size = h->nbuckets * sizeof(h->buckets[0]);

	if (BIHASH_KVP_AT_BUCKET_LEVEL)
		bucket_size +=
		    h->nbuckets * BIHASH_KVP_PER_PAGE *
		    sizeof(BVT(clib_bihash_kv));

	h->buckets = BV(alloc_aligned) (h, bucket_size);
	if (h->buckets == NULL) {
		ebpf_warning("h->buckets alloc memory failed.\n");
		return (-1);
	}
	memset(h->buckets, 0, bucket_size);

	if (BIHASH_KVP_AT_BUCKET_LEVEL) {
		int i, j;
		BVT(clib_bihash_bucket) * b;

		b = h->buckets;

		/*
		 * bucket:
		 * ------  --> b
		 *
		 *
		 *      BVT(clib_bihash_bucket)
		 *      offset = (b + 1) - h->buckets
		 *
		 * ------  --> b + 1 -------
		 *           |
		 *           | clib_bihash_kv
		 *           |_______________
		 * kvp page  |
		 *           | clib_bihash_kv
		 *           |_______________
		 *           |
		 *           | clib_bihash_kv
		 *           |_______________
		 * ----------
		 */
		for (i = 0; i < h->nbuckets; i++) {
			BVT(clib_bihash_kv) * v;
			b->offset =
			    BV(clib_bihash_get_offset) (h, (void *)(b + 1));
			b->refcnt = 1;
			/* Mark all elements free */
			v = (void *)(b + 1);
			for (j = 0; j < BIHASH_KVP_PER_PAGE; j++) {
				BV(clib_bihash_mark_free) (v);
				v++;
			}
			/* Compute next bucket start address */
			b = (void *)(((uint64_t) b) + sizeof(*b) +
				     (BIHASH_KVP_PER_PAGE *
				      sizeof(BVT(clib_bihash_kv))));
		}
	}

	/*
	 * The Store Barrier allows the latest data written in the cache
	 * to be updated in the main memory, making it visible to other threads.
	 */
	CLIB_MEMORY_STORE_BARRIER();
	h->instantiated = 1;

	return (0);
}

int BV(clib_bihash_init2) (BVT(clib_bihash_init2_args) * a) {
	BVT(clib_bihash) * h = a->h;

	a->nbuckets = 1 << (max_log2(a->nbuckets));

	h->name = (uint8_t *) a->name;
	h->nbuckets = a->nbuckets;
	h->log2_nbuckets = max_log2(a->nbuckets);
	h->memory_size = a->memory_size;
	h->instantiated = 0;
	/*
	 * indicates whether to add the current created bihash to the
	 * global bihash list. If set to true, the current bihash will
	 * not be added to the global list, otherwise it will be added
	 * to the global list. The specific function is to control
	 * whether the current bihash is visible to the entire system.
	 */
	h->dont_add_to_all_bihash_list = a->dont_add_to_all_bihash_list;

	alloc_arena(h) = 0;

	if (h->alloc_lock)
		clib_mem_free((void *)h->alloc_lock);

	/*
	 * Set up the lock now, so we can use it to make the first add
	 * thread-safe
	 */
	h->alloc_lock = clib_mem_alloc_aligned("hash_lock", CLIB_CACHE_LINE_BYTES,
					       CLIB_CACHE_LINE_BYTES, NULL);
	if (h->alloc_lock == NULL) {
		ebpf_warning("clib_mem_alloc_aligned() error\n");
		return (-1);
	}

	h->alloc_lock[0] = 0;

	return BV(clib_bihash_instantiate) (h);
}

int BV(clib_bihash_init)
 (BVT(clib_bihash) * h, char *name, uint32_t nbuckets, uint64_t memory_size) {
	BVT(clib_bihash_init2_args) _a, *a = &_a;

	memset(a, 0, sizeof(*a));

	a->h = h;
	a->name = name;
	a->nbuckets = nbuckets;
	a->memory_size = memory_size;

	return BV(clib_bihash_init2) (a);
}

void BV(print_bihash) (BVT(clib_bihash) * h) {
	BVT(clib_bihash_bucket) * b;
	BVT(clib_bihash_value) * v;
	int i, j, k;
	u64 active_elements = 0;
	u64 active_buckets = 0;
	u64 linear_buckets = 0;

	ebpf_info("Hash table '%s'\n", h->name ? h->name : (u8 *) "(unnamed)");

	for (i = 0; i < h->nbuckets; i++) {
		b = BV(clib_bihash_get_bucket) (h, i);
		if (BV(clib_bihash_bucket_is_empty) (b)) {
			continue;
		}

		active_buckets++;

		if (b->linear_search)
			linear_buckets++;
		//ebpf_info
		//    ("[%d]: offset %lu, pages count %d, refcnt %d, linear %d\n",
		//     i, (u64) b->offset, (int)(1 << b->log2_pages),
		//     (int)b->refcnt, (int)b->linear_search);

		v = BV(clib_bihash_get_value) (h, b->offset);
		for (j = 0; j < (1 << b->log2_pages); j++) {
			for (k = 0; k < BIHASH_KVP_PER_PAGE; k++) {
				if (BV(clib_bihash_is_free) (&v->kvp[k])) {
					//ebpf_info ("    %d: empty\n",
					//         j * BIHASH_KVP_PER_PAGE + k);
					continue;
				}
				//u8 kv_str[1024];
				//ebpf_info("    %d: %s\n",
				//	  j * BIHASH_KVP_PER_PAGE + k,
				//	  BV(format_bihash_kvp) (kv_str,
				//				 &(v->kvp[k])));
				active_elements++;
			}
			v++;
		}
	}

	ebpf_info("    %lu active elements %lu active buckets\n",
		  active_elements, active_buckets);
	ebpf_info("    %d free lists, h->freelists elts (clib_bihash_value)\n",
		  vec_len(h->freelists));

	for (i = 0; i < vec_len(h->freelists); i++) {
		u32 nfree = 0;
		BVT(clib_bihash_value) * free_elt;
		u64 free_elt_as_u64 = h->freelists[i];

		while (free_elt_as_u64) {
			free_elt =
			    BV(clib_bihash_get_value) (h, free_elt_as_u64);
			nfree++;
			free_elt_as_u64 = free_elt->next_free_as_u64;
		}

		if (nfree)
			ebpf_info("       [Page Num: %d] %u free elts\n",
				  1 << i, nfree);
	}

	ebpf_info("    %lu linear search buckets\n", linear_buckets);
	u64 CLIB_UNUSED(used_bytes) = alloc_arena_next(h);
	ebpf_info("    arena: base 0x%lx, next %lu\n"
		  "           used %lu b (%lu Mbytes) of %lu b (%lu Mbytes)\n",
		  alloc_arena(h), alloc_arena_next(h),
		  used_bytes, used_bytes >> 20,
		  alloc_arena_size(h), alloc_arena_size(h) >> 20);
}

int BV(clib_bihash_add_or_overwrite_stale)
 (BVT(clib_bihash) * h, BVT(clib_bihash_kv) * add_v,
  int (*stale_callback) (BVT(clib_bihash_kv) *, void *), void *arg) {
	return BV(clib_bihash_add_del_inline) (h, add_v, 1, stale_callback,
					       arg);
}

int BV(clib_bihash_add_with_overwrite_cb) (BVT(clib_bihash) * h,
					   BVT(clib_bihash_kv) * add_v,
					   void (overwrite_cb) (BVT
								(clib_bihash_kv)
								*, void *),
					   void *arg) {
	u64 hash = BV(clib_bihash_hash) (add_v);
	return BV(clib_bihash_add_del_inline_with_hash) (h, add_v, hash, 1, 0,
							 0, overwrite_cb, arg);
}

int BV(clib_bihash_search)
 (BVT(clib_bihash) * h,
  BVT(clib_bihash_kv) * search_key, BVT(clib_bihash_kv) * valuep) {
	return BV(clib_bihash_search_inline_2) (h, search_key, valuep);
}

void BV(clib_bihash_foreach_key_value_pair)
 (BVT(clib_bihash) * h, BV(clib_bihash_foreach_key_value_pair_cb) cb, void *arg) {
	int i, j, k;
	BVT(clib_bihash_bucket) * b;
	BVT(clib_bihash_value) * v;

	for (i = 0; i < h->nbuckets; i++) {
		b = BV(clib_bihash_get_bucket) (h, i);
		if (BV(clib_bihash_bucket_is_empty) (b))
			continue;

		v = BV(clib_bihash_get_value) (h, b->offset);
		for (j = 0; j < (1 << b->log2_pages); j++) {
			for (k = 0; k < BIHASH_KVP_PER_PAGE; k++) {
				if (BV(clib_bihash_is_free) (&v->kvp[k]))
					continue;

				if (BIHASH_WALK_STOP == cb(&v->kvp[k], arg))
					return;
				/*
				 * In case the callback deletes the last entry in the bucket...
				 */
				if (BV(clib_bihash_bucket_is_empty) (b))
					goto doublebreak;
			}
			v++;
		}
	      doublebreak:
		;
	}
}
