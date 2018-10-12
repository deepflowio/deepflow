package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Queue struct {
	queue.OverwriteQueue
	Monitor
}

func (q *Queue) Init(name string, size int, options ...queue.Option) {
	q.Monitor.init(name)
	q.OverwriteQueue.Init(name, size, options...)
}

func (q *Queue) Get() interface{} {
	return q.OverwriteQueue.Get()
}

func (q *Queue) Gets(output []interface{}) int {
	return q.OverwriteQueue.Gets(output)
}

func (q *Queue) Put(items ...interface{}) error {
	q.Monitor.send(items)
	return q.OverwriteQueue.Put(items...)
}
