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
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES
#undef BIHASH_USE_HEAP

#define BIHASH_TYPE _8_16
#define BIHASH_KVP_PER_PAGE 7
#define BIHASH_KVP_AT_BUCKET_LEVEL 1

#ifndef __included_bihash_8_16_h__
#define __included_bihash_8_16_h__

#define __u32 u32
#define __u64 u64
#define __u8  u8
#include "xxhash.h"

/** 8 octet key, 8 octet key value pair */
typedef struct {
	u64 key;		/**< the key */
	u64 value[2];		/**< the value */
} clib_bihash_kv_8_16_t;

static inline void clib_bihash_mark_free_8_16(clib_bihash_kv_8_16_t * v)
{
	v->value[0] = 0xFEEDFACE8BADF00DULL;
}

/** Decide if a clib_bihash_kv_8_16_t instance is free
    @param v- pointer to the (key,value) pair
*/
static inline int clib_bihash_is_free_8_16(clib_bihash_kv_8_16_t * v)
{
	if (v->value[0] == 0xFEEDFACE8BADF00DULL)
		return 1;
	return 0;
}

/** Hash a clib_bihash_kv_8_16_t instance
    @param v - pointer to the (key,value) pair, hash the key (only)
*/
static inline u64 clib_bihash_hash_8_16(clib_bihash_kv_8_16_t * v)
{
	return xxhash(v->key);
}

/** Format a clib_bihash_kv_8_16_t instance
    @param s - u8 * vector under construction
    @param args (vararg) - the (key,value) pair to format
    @return s - the u8 * vector under construction
*/

static inline u8 *format_bihash_kvp_8_16(u8 * s, clib_bihash_kv_8_16_t * v)
{
	sprintf((char *)s, "key %lu value [%lu,%lu]",
		v->key, v->value[0], v->value[1]);
	return s;
}

/** Compare two clib_bihash_kv_8_16_t instances
    @param a - first key
    @param b - second key
*/
static inline int clib_bihash_key_compare_8_16(u64 a, u64 b)
{
	return a == b;
}

#undef __included_bihash_template_h__
#include "bihash_template.h"

#endif /* __included_bihash_8_16_h__ */
