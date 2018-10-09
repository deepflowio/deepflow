package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Duplicator struct {
	bufsize           int
	input             queue.QueueReader
	outputQueues      []queue.QueueWriter
	outputMultiQueues []queue.MultiQueueWriter
	multiQueueSizes   []int
	clone             func(items []interface{}) []interface{}
}

type CloneHelper = func(items []interface{}) []interface{}

// NewDuplicator 从input中拿取数据，推送到outputs中，每次最多拿取bufsize条
func NewDuplicator(bufsize int, input queue.QueueReader, clone CloneHelper) *Duplicator {
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
		bufferClone := d.clone(buffer[:n])
		for _, outQueue := range d.outputQueues {
			outQueue.Put(buffer[:n]...)
		}
		for i, multiQueue := range d.outputMultiQueues {
			broke(multiQueue, d.multiQueueSizes[i], bufferClone[:n])
		}
	}
}

// Start 不停从input接收，发送到outputs
func (d *Duplicator) Start() {
	go d.run()
}
