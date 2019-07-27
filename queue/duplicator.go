package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

// 通过ExtraRefCount避免对象复制，适用于只读场景
type PseudoCloneHelper = func(items []interface{})

type Duplicator struct {
	index             int
	queueBatchSize    int
	inputQueue        queue.QueueReader
	outputMultiQueues []queue.MultiQueueWriter
	pseudoClone       PseudoCloneHelper
}

// NewDuplicator 从input中拿取数据，推送到outputs中，每次最多拿取queueBatchSize条
func NewDuplicator(index, queueBatchSize int, inputQueue queue.QueueReader, pseudoClone PseudoCloneHelper) *Duplicator {
	return &Duplicator{index: index, queueBatchSize: queueBatchSize, inputQueue: inputQueue, pseudoClone: pseudoClone}
}

func (d *Duplicator) AddMultiQueue(output queue.MultiQueueWriter) *Duplicator {
	d.outputMultiQueues = append(d.outputMultiQueues, output)
	return d
}

func (d *Duplicator) run() {
	hashKeys := make([]queue.HashKey, d.queueBatchSize+1)
	hashKeys[0] = queue.HashKey(d.index) // user id

	buffer := make([]interface{}, d.queueBatchSize)
	for {
		n := d.inputQueue.Gets(buffer)

		// 先克隆，再发送，避免在队列中被Release
		for i := 1; i < len(d.outputMultiQueues); i++ {
			d.pseudoClone(buffer[:n])
		}

		for i, item := range buffer[:n] {
			if flow, ok := item.(*datatype.TaggedFlow); ok {
				hashKeys[i+1] = queue.HashKey(flow.QueueHash)
			}
		}
		for _, multiQueue := range d.outputMultiQueues {
			multiQueue.Puts(hashKeys[:n+1], buffer[:n])
		}

		for i := 0; i < n; i++ { // 避免持有对象
			buffer[i] = nil
		}
	}
}

// Start 不停从input接收，发送到outputs
func (d *Duplicator) Start() {
	go d.run()
}
