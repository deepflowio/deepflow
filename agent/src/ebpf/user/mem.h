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

#ifndef _included_clib_mem_h
#define _included_clib_mem_h

#include <malloc.h>
#include <sys/mman.h>
#include "atomic.h"
#include "list.h"

// need install libasan5
//#include <sanitizer/asan_interface.h>

#define CLIB_MEM_VM_MAP_FAILED ((void *) ~0)
#define CLIB_MEM_ERROR (-1)
#define CLIB_MEM_LOG2_MIN_ALIGN (3)
#define CLIB_MEM_MIN_ALIGN	(1 << CLIB_MEM_LOG2_MIN_ALIGN)

typedef enum {
	CLIB_MEM_PAGE_SZ_UNKNOWN = 0,
	CLIB_MEM_PAGE_SZ_DEFAULT = 1,
	CLIB_MEM_PAGE_SZ_DEFAULT_HUGE = 2,
	CLIB_MEM_PAGE_SZ_4K = 12,
	CLIB_MEM_PAGE_SZ_16K = 14,
	CLIB_MEM_PAGE_SZ_64K = 16,
	CLIB_MEM_PAGE_SZ_1M = 20,
	CLIB_MEM_PAGE_SZ_2M = 21,
	CLIB_MEM_PAGE_SZ_16M = 24,
	CLIB_MEM_PAGE_SZ_32M = 25,
	CLIB_MEM_PAGE_SZ_512M = 29,
	CLIB_MEM_PAGE_SZ_1G = 30,
	CLIB_MEM_PAGE_SZ_16G = 34,
} clib_mem_page_sz_t;

typedef struct {
	/* log2 system page size */
	clib_mem_page_sz_t log2_page_sz;

	/* log2 default hugepage size */
	clib_mem_page_sz_t log2_default_hugepage_sz;

	/* total memory bytes statistics*/
	atomic64_t clib_alloc_mem_bytes;
	atomic64_t clib_free_mem_bytes;

#ifdef DF_MEM_DEBUG
	volatile uint32_t *list_lock;
	/* Used for managing all allocated memory.*/
	struct list_head mem_list_head;
#endif
} clib_mem_main_t;


#ifdef DF_MEM_DEBUG
struct mem_list_elem {
	struct list_head list;
	char name[16];
	uword address;
	u32 size;
};

static_always_inline void mem_list_lock(clib_mem_main_t *m)
{
	while (__atomic_test_and_set(m->list_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static_always_inline void mem_list_unlock(clib_mem_main_t *m)
{
	__atomic_clear(m->list_lock, __ATOMIC_RELEASE);
}
#endif

#ifndef __NR_memfd_create
#if defined __x86_64__
#define __NR_memfd_create 319
#elif defined __arm__
#define __NR_memfd_create 385
#elif defined __aarch64__
#define __NR_memfd_create 279
#else
#error "__NR_memfd_create unknown for this architecture"
#endif
#endif

/*
 * The ASAN_POISON_MEMORY_REGION macro defines a function
 * __asan_poison_memory_region() that can fill a specified
 * memory region (including the starting address and length)
 * with invalid values. These values are usually inaccessible
 * values such as 0xAB or 0xCD. If the program attempts to
 * use these invalid values, an error will occur immediately,
 * helping developers to detect potential memory issues.
 *
 * compile with -fsanitize=address
 */
static_always_inline void clib_mem_poison(const void volatile *p, uword s)
{
#ifdef CLIB_SANITIZE_ADDR
	ASAN_POISON_MEMORY_REGION(p, s);
#endif
}

static_always_inline void clib_mem_unpoison(const void volatile *p, uword s)
{
#ifdef CLIB_SANITIZE_ADDR
	ASAN_UNPOISON_MEMORY_REGION(p, s);
#endif
}

always_inline void
clib_mem_vm_free (void *addr, uword size)
{
	munmap (addr, size);
}

void clib_mem_init(void);
uword clib_mem_vm_reserve(uword size, clib_mem_page_sz_t log2_page_sz);
void *clib_mem_realloc_aligned(const char *name, void *p, uword size, u32 align, uword *alloc_sz);
void *clib_mem_alloc_aligned(const char *name, uword size, u32 align, uword *alloc_sz);
void clib_mem_free(void *p);
void get_mem_stat(u64 *alloc_b, u64 *free_b);
#ifdef DF_MEM_DEBUG
void show_mem_list(void);
#endif

#endif /* _included_clib_mem_h */
