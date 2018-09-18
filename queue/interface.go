package queue

type HashKey = uint8

type QueueReader interface {
	Get() interface{}
	Gets([]interface{}) int
}

type QueueWriter interface {
	Put(...interface{}) error
}

type Queue interface {
	QueueReader
	QueueWriter

	Len() int
}

type MultiQueueReader interface {
	Get(HashKey) interface{}
	Gets(HashKey, []interface{}) int
}

type MultiQueueWriter interface {
	Put(HashKey, ...interface{}) error
	Puts([]HashKey, []interface{}) error
}

type MultiQueue interface {
	MultiQueueReader
	MultiQueueWriter

	Len(HashKey) int
}
