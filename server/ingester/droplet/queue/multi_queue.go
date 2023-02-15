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

package queue

import (
	"errors"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type MultiQueue struct {
	queue.FixedMultiQueue
	*Monitor

	readers []queue.QueueReader
	writers []queue.QueueWriter

	itemBatches [][][]interface{}
}

func (q *MultiQueue) Init(name string, size, count, userCount int, unmarshaller Unmarshaller, options ...queue.Option) {
	q.Monitor = &Monitor{}
	q.Monitor.init(name, unmarshaller)
	options = append(options, common.QUEUE_STATS_MODULE_INGESTER)
	q.FixedMultiQueue = queue.NewOverwriteQueues(name, uint8(count), size, options...)

	q.readers = make([]queue.QueueReader, len(q.FixedMultiQueue))
	for i := 0; i < len(q.FixedMultiQueue); i++ {
		q.readers[i] = &Queue{q.FixedMultiQueue[i], q.Monitor}
	}
	q.writers = make([]queue.QueueWriter, len(q.FixedMultiQueue))
	for i := 0; i < len(q.FixedMultiQueue); i++ {
		q.writers[i] = &Queue{q.FixedMultiQueue[i], q.Monitor}
	}

	if count > 1 {
		batchSize := size
		if batchSize > 1024 {
			batchSize = 1024
		}
		q.itemBatches = make([][][]interface{}, userCount)
		for userId, _ := range q.itemBatches {
			q.itemBatches[userId] = make([][]interface{}, count)
			for queueId, _ := range q.itemBatches[userId] {
				q.itemBatches[userId][queueId] = make([]interface{}, 0, batchSize)
			}
		}
	}
}

func (q *MultiQueue) Readers() []queue.QueueReader {
	return q.readers
}

func (q *MultiQueue) Writers() []queue.QueueWriter {
	return q.writers
}

func (q *MultiQueue) Get(key queue.HashKey) interface{} {
	return q.FixedMultiQueue.Get(key)
}

func (q *MultiQueue) Gets(key queue.HashKey, output []interface{}) int {
	return q.FixedMultiQueue.Gets(key, output)
}

func (q *MultiQueue) Put(key queue.HashKey, items ...interface{}) error {
	q.Monitor.send(items)
	return q.FixedMultiQueue.Put(key, items...)
}

// The userId key must be placed in keys[0] (with item keys)
func (q *MultiQueue) Puts(keys []queue.HashKey, items []interface{}) error {
	if len(keys) <= 1 || len(keys)-1 != len(items) {
		return errors.New("Requested keys and items are invalid")
	}
	userId := keys[0]
	keys = keys[1:]

	q.Monitor.send(items)
	userCount := uint8(len(q.itemBatches))
	if userCount == 0 {
		return q.FixedMultiQueue.Put(keys[0], items...)
	}

	itemBatches := q.itemBatches[userId%userCount]
	batchCount := uint8(len(itemBatches))
	for i, item := range items {
		index := keys[i] % batchCount
		itemBatches[index] = append(itemBatches[index], item)
		itemBatch := itemBatches[index]
		if len(itemBatch) == cap(itemBatch) {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	for index, itemBatch := range itemBatches {
		if len(itemBatch) > 0 {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (q *MultiQueue) Len(key queue.HashKey) int {
	return q.FixedMultiQueue.Len(key)
}
