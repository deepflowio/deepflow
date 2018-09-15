package sender

import (
	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/message/zero"
)

type ZeroDocumentMarshaller struct {
	input    queue.QueueReader
	outputs  []queue.QueueWriter
	sequence uint32
}

// NewZeroDocumentMarshaller 从input读取app.Document，转换为pb.ZeroDocument结构，复制并推送到每一个outputs里
func NewZeroDocumentMarshaller(input queue.QueueReader, outputs ...queue.QueueWriter) *ZeroDocumentMarshaller {
	return &ZeroDocumentMarshaller{input, outputs, 1}
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
				code := doc.Tag.(*zerodoc.Tag).Code
				header := &zero.ZeroHeader{
					Timestamp: proto.Uint32(doc.Timestamp),
					Sequence:  proto.Uint32(m.sequence),
					// TODO: 修改hash算法
					Hash: proto.Uint32(uint32((code >> 32) | code)),
				}
				message, err := proto.Marshal(header)
				if err != nil {
					log.Warning(err)
					continue
				}
				b, err := messenger.Marshal(doc)
				if err != nil {
					log.Warning(err)
					continue
				}
				message = append(message, b...)
				outBuffer[nOut] = message
				nOut++
				m.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be []byte", doc)
			}
		}
		for _, outQueue := range m.outputs {
			outQueue.Put(outBuffer[:nOut]...)
		}
	}
}
