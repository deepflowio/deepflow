package queue

type QueueReader interface {
	Get() interface{}
	Gets([]interface{}) int
}

type QueueWriter interface {
	Put(items ...interface{}) error
}

type Queue interface {
	QueueReader
	QueueWriter

	Len() int
}
