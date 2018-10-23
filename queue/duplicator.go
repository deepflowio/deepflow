package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

// 通过ExtraRefCount避免对象复制，适用于只读场景
type PseudoCloneHelper = func(items []interface{})

type Duplicator struct {
	bufsize           int
	input             queue.QueueReader
	outputQueues      []queue.QueueWriter
	outputMultiQueues []queue.MultiQueueWriter
	multiQueueSizes   []int
	clone             PseudoCloneHelper
}

// NewDuplicator 从input中拿取数据，推送到outputs中，每次最多拿取bufsize条
func NewDuplicator(bufsize int, input queue.QueueReader, clone PseudoCloneHelper) *Duplicator {
	return &Duplicator{bufsize: bufsize, input: input, clone: clone}
}

func (d *Duplicator) AddQueue(output queue.QueueWriter) *Duplicator {
	d.outputQueues = append(d.outputQueues, output)
	return d
}

func (d *Duplicator) AddMultiQueue(output queue.MultiQueueWriter, size int) *Duplicator {
	d.outputMultiQueues = append(d.outputMultiQueues, output)
	d.multiQueueSizes = append(d.multiQueueSizes, size)
	return d
}

func broke(output queue.MultiQueueWriter, size int, items []interface{}) {
	itemSize := len(items)
	if itemSize == 0 {
		return
	}
	itemPerQueue := itemSize/size + 1
	for i := 0; i < size; i++ {
		start := itemPerQueue * i
		if start >= itemSize {
			break
		}
		end := itemPerQueue * (i + 1)
		if end > itemSize {
			end = itemSize
		}
		output.Put(queue.HashKey(i), items[start:end]...)
	}
}

func (d *Duplicator) run() {
	buffer := make([]interface{}, d.bufsize)
	for {
		n := d.input.Gets(buffer)
		log.Debugf("%d items received", n)
		for _ = range d.outputMultiQueues {
			d.clone(buffer[:n]) // 先克隆，再发送，避免在队列中被Release
		}

		for _, outQueue := range d.outputQueues {
			outQueue.Put(buffer[:n]...)
		}
		for i, multiQueue := range d.outputMultiQueues {
			broke(multiQueue, d.multiQueueSizes[i], buffer[:n])
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
