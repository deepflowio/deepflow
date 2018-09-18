package queue

import (
	"errors"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type MultiQueue struct {
	queue.FixedMultiQueue
	Monitor

	itemBatches [][]interface{}
}

func (q *MultiQueue) Init(name string, size int, count int) {
	q.Monitor.init(name)
	q.FixedMultiQueue = queue.NewOverwriteQueues(name, uint8(count), size)

	if count > 1 {
		batchSize := size
		if batchSize > 1024 {
			batchSize = 1024
		}
		q.itemBatches = make([][]interface{}, len(q.FixedMultiQueue))
		for index, _ := range q.itemBatches {
			q.itemBatches[index] = make([]interface{}, 0, batchSize)
		}
	}
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

func (q *MultiQueue) Puts(keys []queue.HashKey, items []interface{}) error {
	if len(keys) != len(items) {
		return errors.New("Requested keys and items are invalid")
	}

	q.Monitor.send(items)
	keyMask := uint8(len(q.FixedMultiQueue) - 1)
	if keyMask == 0 {
		return q.FixedMultiQueue.Put(keys[0], items...)
	}

	for i, item := range items {
		index := keys[i] & keyMask
		q.itemBatches[index] = append(q.itemBatches[index], item)
		itemBatch := q.itemBatches[index]
		if len(itemBatch) == cap(itemBatch) {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			q.itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	for index, itemBatch := range q.itemBatches {
		if len(itemBatch) > 0 {
			err := q.FixedMultiQueue.Put(queue.HashKey(index), itemBatch...)
			q.itemBatches[index] = itemBatch[:0]
			if err != nil {
				return err
			}
		}
	}
	return nil
}
