/*
 * Copyright (c) 2024 Yunshan Networks
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

/**
 * 哈希索引的多队列实现
 */
package queue

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/deepflowio/deepflow/server/libs/stats"
)

type FixedMultiQueue []*OverwriteQueue

func (q FixedMultiQueue) entry(key HashKey) *OverwriteQueue {
	return q[key&(uint8(len(q)-1))]
}

func (q FixedMultiQueue) Get(key HashKey) interface{} {
	return q.entry(key).Get()
}

func (q FixedMultiQueue) Gets(key HashKey, output []interface{}) int {
	return q.entry(key).Gets(output)
}

func (q FixedMultiQueue) Put(key HashKey, items ...interface{}) error {
	return q.entry(key).Put(items...)
}

func (q FixedMultiQueue) Puts(keys []HashKey, items []interface{}) error {
	return errors.New("Not implemented")
}

func (q FixedMultiQueue) Len(key HashKey) int {
	return q.entry(key).Len()
}

func (q FixedMultiQueue) Close() error {
	for _, e := range q {
		e.Close()
	}
	return nil
}

// count和queueSize要求是2的幂以避免求余计算，如果不是2的幂将会隐式转换为2的幂来构造
// HashKey要求映射到count范围内，否则MultiQueue只会取低比特位
func NewOverwriteQueues(module string, count uint8, queueSize int, options ...Option) FixedMultiQueue {
	if count > MAX_QUEUE_COUNT {
		panic(fmt.Sprintf("queueCount超出最大限制%d", MAX_QUEUE_COUNT))
	}

	size := int(count)
	queues := make([]*OverwriteQueue, size)
	for i := 0; i < size; i++ {
		opts := append(options, stats.OptionStatTags{"index": strconv.Itoa(i)})
		queue := new(OverwriteQueue)
		queue.Init(module, queueSize, opts...)
		queues[i] = queue
	}
	tableSize := 1
	for tableSize < size {
		tableSize <<= 1
	}
	table := make(FixedMultiQueue, tableSize)
	for i := 0; i < tableSize; i++ {
		table[i] = queues[i%size]
	}
	return table
}
