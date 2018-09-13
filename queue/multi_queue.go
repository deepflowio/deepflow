package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type MultiQueue struct {
	queue.FixedMultiQueue

	Monitor
}

func (q *MultiQueue) Init(name string, size int, count int) {
	q.Monitor.init(name)
	q.FixedMultiQueue = queue.NewOverwriteQueues(name, uint8(count), size)
}

func (q *MultiQueue) Put(key queue.HashKey, items ...interface{}) error {
	q.Monitor.send(items)
	return q.FixedMultiQueue.Put(key, items...)
}
