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

#define BIHASH_TYPE _24_8
#define BIHASH_KVP_PER_PAGE 4
#define BIHASH_KVP_AT_BUCKET_LEVEL 0

#ifndef __included_bihash_24_8_h__
#define __included_bihash_24_8_h__

#define __u32 u32
#define __u64 u64
#define __u8  u8
#include "xxhash.h"

typedef struct {
	u64 key[3];
	u64 value;
} clib_bihash_kv_24_8_t;

static inline void clib_bihash_mark_free_24_8(clib_bihash_kv_24_8_t * v)
{
	v->value = 0xFEEDFACE8BADF00DULL;
}

static inline int clib_bihash_is_free_24_8(const clib_bihash_kv_24_8_t * v)
{
	if (v->value == 0xFEEDFACE8BADF00DULL)
		return 1;
	return 0;
}

static inline u64 clib_bihash_hash_24_8(const clib_bihash_kv_24_8_t * v)
{
	u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2];
	return xxhash(tmp);
}

static inline u8 *format_bihash_kvp_24_8(u8 * s, clib_bihash_kv_24_8_t * v)
{
	sprintf((char *)s, "key %lu %lu %lu value %lu",
		v->key[0], v->key[1], v->key[2], v->value);
	return s;
}

static inline int clib_bihash_key_compare_24_8(u64 * a, u64 * b)
{
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
}

#undef __included_bihash_template_h__
#include "bihash_template.h"

#endif /* __included_bihash_24_8_h__ */
