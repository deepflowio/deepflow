package queue

import (
	"server/libs/queue"
)

type Queue struct {
	*queue.OverwriteQueue
	*Monitor
}

func (q *Queue) Init(name string, size int, unmarshaller Unmarshaller, options ...queue.Option) {
	q.Monitor = &Monitor{}
	q.Monitor.init(name, unmarshaller)
	q.OverwriteQueue = &queue.OverwriteQueue{}
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

func (q *Queue) Len() int {
	return q.OverwriteQueue.Len()
}
