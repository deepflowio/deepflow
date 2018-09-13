package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Queue struct {
	queue.OverwriteQueue
	Monitor
}

func (q *Queue) Init(name string, size int) {
	q.Monitor.init(name)
	q.OverwriteQueue.Init(name, size)
}

func (q *Queue) Put(items ...interface{}) error {
	q.Monitor.send(items)
	return q.OverwriteQueue.Put(items...)
}
