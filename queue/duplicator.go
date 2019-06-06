package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

// 通过ExtraRefCount避免对象复制，适用于只读场景
type PseudoCloneHelper = func(items []interface{})

type Duplicator struct {
	bufsize           int
	input             queue.QueueReader
	outputQueues      []queue.QueueWriter
	hasMultiQueue     bool
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
	d.hasMultiQueue = true
	d.outputMultiQueues = append(d.outputMultiQueues, output)
	d.multiQueueSizes = append(d.multiQueueSizes, size)
	return d
}

func (d *Duplicator) run() {
	hashKeys := make([]queue.HashKey, d.bufsize+1)
	hashKeys[0] = 0 // user id
	buffer := make([]interface{}, d.bufsize)
	for {
		n := d.input.Gets(buffer)
		for _ = range d.outputMultiQueues {
			d.clone(buffer[:n]) // 先克隆，再发送，避免在队列中被Release
		}

		for _, outQueue := range d.outputQueues {
			outQueue.Put(buffer[:n]...)
		}
		if d.hasMultiQueue {
			for i, item := range buffer[:n] {
				if flow, ok := item.(*datatype.TaggedFlow); ok {
					hashKeys[i+1] = queue.HashKey(flow.Hash)
				}
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
