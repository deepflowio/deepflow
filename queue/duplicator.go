package queue

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Duplicator struct {
	bufsize int
	input   queue.QueueReader
	outputs []queue.QueueWriter
}

// NewDuplicator 从input中拿取数据，推送到outputs中，每次最多拿取bufsize条
func NewDuplicator(bufsize int, input queue.QueueReader, outputs ...queue.QueueWriter) *Duplicator {
	return &Duplicator{bufsize, input, outputs}
}

func (d *Duplicator) run() {
	buffer := make([]interface{}, d.bufsize)
	for {
		n := d.input.Gets(buffer)
		log.Debugf("%d items received", n)
		for _, outQueue := range d.outputs {
			outQueue.Put(buffer[:n]...)
		}
	}
}

// Start 不停从input接收，发送到outputs
func (d *Duplicator) Start() {
	go d.run()
}
