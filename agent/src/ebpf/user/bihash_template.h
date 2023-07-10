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

/*
 * Note: to instantiate the template multiple times in a single file,
 * #undef __included_bihash_template_h__...
 */

#ifndef __included_bihash_template_h__
#define __included_bihash_template_h__

#ifndef BIHASH_TYPE
#error BIHASH_TYPE not defined
#endif

#include "types.h"

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)

#define _bvs(a,b) struct a##b
#define __bvs(a,b) _bvs(a,b)
#define BVS(a) __bvs(a,BIHASH_TYPE)

/* default is 2MB, use 30 for 1GB */
#ifndef BIHASH_LOG2_HUGEPAGE_SIZE
#define BIHASH_LOG2_HUGEPAGE_SIZE 21
#endif

/*
 * BIHASH_KVP_AT_BUCKET_LEVEL is a macro
 * that indicates how key-value pairs are stored in each bucket
 * of a hash table.
 *
 * Specifically, when BIHASH_KVP_AT_BUCKET_LEVEL is defined as 1,
 * each bucket in the hash table stores a key-value pair and the
 * bucket size is fixed to a power of 2.
 *
 * On the other hand, when BIHASH_KVP_AT_BUCKET_LEVEL is defined
 * as 0, each bucket in the hash table stores a pointer to the
 * key-value pair, while the key-value pairs are stored in
 * separate memory locations. This approach can save memory
 * but may impact the speed of accessing key-value pairs.
 */

/* bihash memory max : 68,719,476,736 bytes */
#define BIHASH_BUCKET_OFFSET_BITS 36

/*
 * BVT(clib_bihash_bucket):
 * 
 *  
 * @offset: the offset of the first element in the bucket,
 * taking up BIHASH_BUCKET_OFFSET_BITS bits. The offset is
 * calculated relative to the start address of the hash table(alloc_arena(h)).
 *
 * @lock: the lock flag of the bucket, taking up 1 bit. In
 * multi-threaded concurrent access to the hash table, the bucket
 * needs to be locked to prevent multiple threads from accessing
 * the same bucket at the same time, resulting in inconsistent data.
 * The lock flag is used to record the lock state of the bucket,
 * 1 means locked, and 0 means unlocked.
 *
 * @linear_search: whether the bucket uses linear search algorithm,
 * taking up 1 bit. Linear search algorithm is a search algorithm
 * that traverses the key-value pairs in the bucket one by one until
 * the target key-value pair is found. Compared with other efficient
 * hash search algorithms, linear search algorithm is less efficient,
 * but for smaller buckets, linear search algorithm may be more suitable.
 * The linear_search flag is used to record the search algorithm type
 * used by the bucket, 1 means using linear search algorithm, and 0
 * means using other efficient hash search algorithms.
 *
 * @log2_pages: the log2 of the number of pages corresponding to the
 * bucket, taking up 8 bits.
 *                page | kv - pair |
 *                |    | ----------|
 *                |    | kv - pair |
 *                |    | ----------|
 *                |    | ... ...   |
 * 1 << log2_page      =============
 *                page | kv - pair |
 *                |    |-----------|
 *                |     ... ...
 *                ...
 * log2_page represents the exponent of the number of pages
 * (i.e. the number of pages is 1 << log2_page), and each page
 * contains IHASH_KVP_PER_PAGE kv-pairs. The size of the storage
 * in the bucket is expandable.
 *
 * @refcnt: the reference count of the bucket, taking up 16 bits.
 * Reference counting is a memory management technique used to track
 * whether an object in memory is still referenced by other objects.
 * In the hash table, each bucket is an object that may be shared by
 * multiple threads or hash tables. refcnt records the reference count
 * of the bucket, each time a thread or hash table references the bucket,
 * its reference count is incremented; when the reference count is 0,
 * it means that the bucket is no longer referenced by any object and can
 * be released.
 */
typedef struct {
	union {
		struct {
			u64 offset:BIHASH_BUCKET_OFFSET_BITS;
			u64 lock:1;
			u64 linear_search:1;
			u64 log2_pages:8;
			u64 refcnt:16;
		};
		u64 as_u64;
	};
} BVT(clib_bihash_bucket);

typedef struct BV (clib_bihash_value) {
	union {
		BVT(clib_bihash_kv) kvp[BIHASH_KVP_PER_PAGE];
		u64 next_free_as_u64;
	};
} BVT(clib_bihash_value);

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
	/*
	 * Backing store allocation. Since bihash manages its own
	 * freelists, we simple dole out memory starting from alloc_arena[alloc_arena_next].
	 */
	u64 alloc_arena_next;	/* Next offset from alloc_arena to allocate, definitely NOT a constant */
	u64 alloc_arena_size;	/* Size of the arena */
	u64 alloc_arena_mapped;	/* Size of the mapped memory in the arena */
	/* Two SVM pointers stored as 8-byte integers */
	u64 alloc_lock_as_u64;
	u64 buckets_as_u64;
	/* freelist list-head arrays/vectors */
	u64 freelists_as_u64;
	u32 nbuckets;	/* Number of buckets */
	/* Set when header valid */
	volatile u32 ready;
	u64 pad[1];
}) BVT (clib_bihash_shared_header);
/* *INDENT-ON* */

typedef BVS(clib_bihash)
{
	BVT(clib_bihash_bucket) * buckets;
	volatile u32 *alloc_lock;
	/*
	 * bihash is a hash table implementation used to map key-value
	 * pairs to buckets. "working_copies" refers to the working copies
	 * of bihash, which is a pointer to two hash tables used to support
	 * concurrent read and write operations. When multiple threads access
	 * bihash concurrently, each thread uses its own working copies to
	 * perform read and write operations, avoiding competition and
	 * improving concurrency performance. (is vec)
	 */
	BVT(clib_bihash_value) ** working_copies;
	/*
	 * "working_copy_lengths" in bihash represents the number of entries
	 * in each bucket of the hash table. This variable is updated during
	 * the dynamic adjustment process of the hash table to ensure efficient
	 * operations while maintaining load balancing. Specifically, when the
	 * number of entries in a bucket exceeds a certain threshold, VPP
	 * dynamically increases the size of the hash table and rehashes all
	 * entries to ensure that the number of entries in each bucket remains
	 * within an acceptable range.
	 */
	int *working_copy_lengths;
	BVT (clib_bihash_bucket) saved_bucket;

	u32 nbuckets;
	u32 log2_nbuckets;
	u64 memory_size;
	u8 *name;
	/* freelists[log2_page]: offsetting the mmap base address (alloc_arena) */
	u64 *freelists;
	BVT(clib_bihash_shared_header) sh;
	volatile u8 instantiated;
	/*
	 * indicates whether to add the current created bihash
	 * to the global bihash list(vec: clib_all_bihashes).
	 */
	u8 dont_add_to_all_bihash_list;
	u64 alloc_arena;	/* Base of the allocation arena */
	u64 add_increment_stat;	/* kv pair add */
	u64 replace_increment_stat;	/* kv pair replace old */
	u64 del_increment_stat;	/* kv pair delete */
	u64 working_copy_lost_stat;
	u64 split_add_increment_stat;
	u64 splits_increment_stat;
	u64 resplit_increment_stat;
	u64 linear_increment_stat;
	/* hash hit count, search hit */
	u64 hit_hash_count;

	/* current hash's elements count */
	u64 hash_elems_count;

	void *private; /* It is used to store the user's private data. */
} BVT(clib_bihash);

typedef struct {
	BVT(clib_bihash) * h;
	char *name;
	u32 nbuckets;
	u64 memory_size;
	u8 instantiate_immediately;
	u8 dont_add_to_all_bihash_list;
} BVT(clib_bihash_init2_args);

#if BIHASH_32_64_SVM
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena_mapped
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) (((h)->sh)->alloc_arena_next)
#define alloc_arena_size(h) (((h)->sh)->alloc_arena_size)
#define alloc_arena_mapped(h) (((h)->sh)->alloc_arena_mapped)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0xFEEDFACE
#else
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena_mapped
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) ((h)->sh.alloc_arena_next)
#define alloc_arena_size(h) ((h)->sh.alloc_arena_size)
#define alloc_arena_mapped(h) ((h)->sh.alloc_arena_mapped)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0
#endif

#define alloc_arena(h) ((h)->alloc_arena)

static inline u64 BV(clib_bihash_get_offset) (BVT(clib_bihash) * h, void *v) {
	u8 * hp, *vp;

	hp = (u8 *) (u64) alloc_arena(h);
	vp = (u8 *) v;

	return vp - hp;
}

static inline
BVT(clib_bihash_bucket) *
BV(clib_bihash_get_bucket) (BVT(clib_bihash) * h, u64 hash)
{
#if BIHASH_KVP_AT_BUCKET_LEVEL
	uword offset;
	offset = (hash & (h->nbuckets - 1));	// offset bucket index
	offset = offset * (sizeof(BVT(clib_bihash_bucket))
			   +
			   (BIHASH_KVP_PER_PAGE * sizeof(BVT(clib_bihash_kv))));
	return ((BVT(clib_bihash_bucket) *) (((u8 *) h->buckets) + offset));
#else
	return h->buckets + (hash & (h->nbuckets - 1));
#endif
}

static inline void BV(clib_bihash_lock_bucket) (BVT(clib_bihash_bucket) * b) {
	/* *INDENT-OFF* */
	BVT (clib_bihash_bucket) mask = { .lock = 1 };
	/* *INDENT-ON* */
	u64 old;

try_again:
	old = clib_atomic_fetch_or(&b->as_u64, mask.as_u64);

	if (PREDICT_FALSE(old & mask.as_u64)) {
		/* somebody else flipped the bit, try again */
		CLIB_PAUSE();
		goto try_again;
	}
}

static inline void BV(clib_bihash_unlock_bucket)
 (BVT(clib_bihash_bucket) * b) {
	b->lock = 0;
}

static inline int BV(clib_bihash_bucket_is_empty)
 (BVT(clib_bihash_bucket) * b) {
	/* Note: applied to locked buckets, test offset */
	if (BIHASH_KVP_AT_BUCKET_LEVEL == 0)
		return b->offset == 0;
	else
		return (b->log2_pages == 0 && b->refcnt == 1);
}

static inline void BV(clib_bihash_alloc_lock) (BVT(clib_bihash) * h) {
	/* use GCC built-in atomic operation function */
	while (__atomic_test_and_set(h->alloc_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void BV(clib_bihash_alloc_unlock) (BVT(clib_bihash) * h) {
	__atomic_clear(h->alloc_lock, __ATOMIC_RELEASE);
}

static inline void *BV(clib_bihash_get_value) (BVT(clib_bihash) * h,
					       uword offset) {
	u8 *hp = (u8 *) (uword) alloc_arena(h);
	u8 *vp = hp + offset;

	return (void *)vp;
}

static inline int BV(clib_bihash_search_inline_2_with_hash)
 (BVT(clib_bihash) * h,
  u64 hash, BVT(clib_bihash_kv) * search_key, BVT(clib_bihash_kv) * valuep) {
	BVT(clib_bihash_kv) rv;
	BVT(clib_bihash_value) * v;
	BVT(clib_bihash_bucket) * b;
	int i, limit;

	/* *INDENT-OFF* */
	static const BVT (clib_bihash_bucket) mask = {
		.linear_search = 1,
		.log2_pages = -1
	};
	/* *INDENT-ON* */

	ASSERT(valuep);

	b = BV(clib_bihash_get_bucket) (h, hash);

	if (PREDICT_FALSE(BV(clib_bihash_bucket_is_empty) (b)))
		return -1;

	if (PREDICT_FALSE(b->lock)) {
		volatile BVT(clib_bihash_bucket) * bv = b;
		while (bv->lock)
			CLIB_PAUSE();
	}

	v = BV(clib_bihash_get_value) (h, b->offset);

	/* If the bucket has unresolvable collisions, use linear search */
	limit = BIHASH_KVP_PER_PAGE;

	if (PREDICT_FALSE(b->as_u64 & mask.as_u64)) {
		if (PREDICT_FALSE(b->linear_search))
			limit <<= b->log2_pages;
		else
			v += extract_bits(hash, h->log2_nbuckets,
					  b->log2_pages);
	}

	for (i = 0; i < limit; i++) {
		if (BV(clib_bihash_key_compare)
		    (v->kvp[i].key, search_key->key)) {
			rv = v->kvp[i];
			if (BV(clib_bihash_is_free) (&rv))
				return -1;
			*valuep = rv;
			return 0;
		}
	}
	return -1;
}

static inline int BV(clib_bihash_search_inline_2)
 (BVT(clib_bihash) * h,
  BVT(clib_bihash_kv) * search_key, BVT(clib_bihash_kv) * valuep) {
	u64 hash;

	hash = BV(clib_bihash_hash) (search_key);

	return BV(clib_bihash_search_inline_2_with_hash) (h, hash, search_key,
							  valuep);
}

int BV(clib_bihash_init)
 (BVT(clib_bihash) * h, char *name, uint32_t nbuckets, uint64_t memory_size);

int BV(clib_bihash_add_del)
 (BVT(clib_bihash) * h, BVT(clib_bihash_kv) * add_v, int is_add);

void BV(print_bihash) (BVT(clib_bihash) * h);

int BV(clib_bihash_search)
 (BVT(clib_bihash) * h,
  BVT(clib_bihash_kv) * search_key, BVT(clib_bihash_kv) * valuep);

#define BIHASH_WALK_STOP 0
#define BIHASH_WALK_CONTINUE 1

/**
 * Calback function for walking a bihash table
 *
 * @param kv - KV pair visited
 * @param ctx - Context passed to the walk
 * @return BIHASH_WALK_CONTINUE to continue BIHASH_WALK_STOP to stop
 */
typedef int (*BV(clib_bihash_foreach_key_value_pair_cb)) (BVT(clib_bihash_kv) *kv,
							  void *ctx);

void BV(clib_bihash_free) (BVT(clib_bihash) * h);
void BV(clib_bihash_foreach_key_value_pair)
 (BVT(clib_bihash) * h, BV(clib_bihash_foreach_key_value_pair_cb) cb, void *arg);

#endif /* __included_bihash_template_h__ */
