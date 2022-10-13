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

#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#include <stdint.h>

/* Memory access barrier */
#define barrier()                 (__sync_synchronize())
/* 原子获取 */
/* Atoms to obtain */
#define AO_GET(ptr)               ({ __typeof__(*(ptr)) volatile *_val = (ptr); barrier(); (*_val); })
/* 原子设置，如果原值和新值不一样则设置 */
/* Atomic setting, if the original value is different from the new value */
#define AO_SET(ptr, value)        ((void)__sync_lock_test_and_set((ptr), (value)))
/* 原子比较交换，如果当前值等于旧值，则新值被设置，返回旧值，否则返回新值*/
/* Atomic comparison swaps, if the current value is equal to the old value,
 * the new value is set and the old value is returned, otherwise the new value is returned
 */
#define AO_CAS(ptr, comp, value)  ((__typeof__(*(ptr)))__sync_val_compare_and_swap((ptr), (comp), (value)))
/* 原子比较交换，如果当前值等于旧指，则新值被设置，返回真值，否则返回假 */
/* If the current value is equal to the old digit, the new value is set and returns true, otherwise false */
#define AO_CASB(ptr, comp, value) (__sync_bool_compare_and_swap((ptr), (comp), (value)) != 0 ? true : false)
/* 原子清零 */
/* Atomic reset */
#define AO_CLEAR(ptr)             ((void)__sync_lock_release((ptr)))
/* 通过值与旧值进行算术与位操作，返回新值 */
/* Returns the new value by performing arithmetic and bit operations on the value and the old value */
#define AO_ADD_F(ptr, value)      ((__typeof__(*(ptr)))__sync_add_and_fetch((ptr), (value)))
#define AO_SUB_F(ptr, value)      ((__typeof__(*(ptr)))__sync_sub_and_fetch((ptr), (value)))
#define AO_OR_F(ptr, value)       ((__typeof__(*(ptr)))__sync_or_and_fetch((ptr), (value)))
#define AO_AND_F(ptr, value)      ((__typeof__(*(ptr)))__sync_and_and_fetch((ptr), (value)))
#define AO_XOR_F(ptr, value)      ((__typeof__(*(ptr)))__sync_xor_and_fetch((ptr), (value)))
/* 通过值与旧值进行算术与位操作，返回旧值 */
/* Returns the old value by performing arithmetic and bit operations on the value and the old value */
#define AO_F_ADD(ptr, value)      ((__typeof__(*(ptr)))__sync_fetch_and_add((ptr), (value)))
#define AO_F_SUB(ptr, value)      ((__typeof__(*(ptr)))__sync_fetch_and_sub((ptr), (value)))
#define AO_F_OR(ptr, value)       ((__typeof__(*(ptr)))__sync_fetch_and_or((ptr), (value)))
#define AO_F_AND(ptr, value)      ((__typeof__(*(ptr)))__sync_fetch_and_and((ptr), (value)))
#define AO_F_XOR(ptr, value)      ((__typeof__(*(ptr)))__sync_fetch_and_xor((ptr), (value)))
/* 忽略返回值，算术和位操作 */
/* Ignore return value, arithmetic, and bit operations */
#define AO_INC(ptr)                 ((void)AO_ADD_F((ptr), 1))
#define AO_DEC(ptr)                 ((void)AO_SUB_F((ptr), 1))
#define AO_ADD(ptr, val)            ((void)AO_ADD_F((ptr), (val)))
#define AO_SUB(ptr, val)            ((void)AO_SUB_F((ptr), (val)))
#define AO_OR(ptr, val)             ((void)AO_OR_F((ptr), (val)))
#define AO_AND(ptr, val)            ((void)AO_AND_F((ptr), (val)))
#define AO_XOR(ptr, val)            ((void)AO_XOR_F((ptr), (val)))

#define mb() _mm_mfence()

#define wmb() _mm_sfence()

#define rmb() _mm_lfence()

#define smp_mb() mb()

#define smp_wmb() barrier()

#define smp_rmb() barrier()

#define io_mb() mb()

#define io_wmb() barrier()
/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int32_t cnt;
			      /**< An internal counter value. */
} atomic32_t;

/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int64_t cnt;
			       /**< Internal counter value. */
} atomic64_t;

/*------------------------- 32 bit atomic operations -------------------------*/

static inline int
atomic32_cmpset(volatile uint32_t * dst, uint32_t exp, uint32_t src)
{
	if (AO_CASB(dst, exp, src))
		return 1;

	return 0;
}

static inline int atomic32_test_and_set(atomic32_t * v)
{
	return atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

static inline int
atomic64_cmpset(volatile uint64_t * dst, uint64_t exp, uint64_t src)
{
	if (AO_CASB(dst, exp, src))
		return 1;

	return 0;
}

static inline void atomic64_init(atomic64_t * v)
{
	AO_SET(&v->cnt, 0);
}

static inline int64_t atomic64_read(atomic64_t * v)
{
	return AO_GET(&v->cnt);
}

static inline void atomic64_set(atomic64_t * v, int64_t new_value)
{
	AO_SET(&v->cnt, new_value);
}

static inline void atomic64_add(atomic64_t * v, int64_t inc)
{
	AO_ADD(&v->cnt, inc);
}

static inline void atomic64_sub(atomic64_t * v, int64_t dec)
{
	AO_SUB(&v->cnt, dec);
}

static inline void atomic64_inc(atomic64_t * v)
{
	AO_INC(&v->cnt);
}

static inline void atomic64_dec(atomic64_t * v)
{
	AO_DEC(&v->cnt);
}

#endif /* _ATOMIC_H_ */
