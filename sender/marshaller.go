package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type ZeroDocumentMarshaller struct {
	input   queue.QueueReader
	outputs []queue.QueueWriter
}

// NewZeroDocumentMarshaller 从input读取app.Document，转换为pb.ZeroDocument结构，复制并推送到每一个outputs里
func NewZeroDocumentMarshaller(input queue.QueueReader, outputs ...queue.QueueWriter) *ZeroDocumentMarshaller {
	return &ZeroDocumentMarshaller{input, outputs}
}

// Start 不停从input接收，发送到outputs
func (m *ZeroDocumentMarshaller) Start() {
	buffer := make([]interface{}, QUEUE_GET_SIZE)
	outBuffer := make([]interface{}, QUEUE_GET_SIZE)
	for {
		n := m.input.Gets(buffer)
		log.Debugf("%d docs received", n)
		nOut := 0
		for _, e := range buffer[:n] {
			if doc, ok := e.(*app.Document); ok {
				b, err := messenger.Marshal(doc)
				if err != nil {
					log.Warning(err)
					continue
				}
				outBuffer[nOut] = b
				nOut++
			} else {
				log.Warningf("Invalid message type %T, should be []byte", doc)
			}
		}
		for _, outQueue := range m.outputs {
			outQueue.Put(outBuffer[:nOut]...)
		}
	}
}
