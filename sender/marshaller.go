package sender

import (
	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
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
	outBuffer0 := make([]interface{}, QUEUE_GET_SIZE)
	outBuffer1 := make([]interface{}, QUEUE_GET_SIZE)

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
				bytes := utils.AcquireByteBuffer()
				if _, err := header.MarshalTo(bytes.Use(header.Size())); err != nil {
					utils.ReleaseByteBuffer(bytes)
					app.ReleaseDocument(doc)
					log.Warning(err)
					continue
				}
				err := messenger.Marshal(doc, bytes)
				app.ReleaseDocument(doc)
				if err != nil {
					utils.ReleaseByteBuffer(bytes)
					log.Warning(err)
					continue
				}
				outBuffer0[nOut] = bytes
				nOut++
				m.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be []byte", doc)
			}
		}

		if len(m.outputs) > 1 {
			for _, q := range m.outputs[1:] {
				// 复制ByteBuffer，使得消费者能独立Release，避免GC
				for i, _ := range outBuffer0[:nOut] {
					outBuffer1[i] = utils.CloneByteBuffer(outBuffer0[i].(*utils.ByteBuffer))
				}
				q.Put(outBuffer1[:nOut]...)
			}
		}
		m.outputs[0].Put(outBuffer0[:nOut]...)
	}
}
