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
	input    queue.MultiQueueReader
	hashKey  queue.HashKey
	outputs  []queue.QueueWriter
	sequence uint32
}

// NewZeroDocumentMarshaller 从input读取app.Document，转换为pb.ZeroDocument结构，复制并推送到每一个outputs里
func NewZeroDocumentMarshaller(input queue.MultiQueueReader, hashKey queue.HashKey, outputs ...queue.QueueWriter) *ZeroDocumentMarshaller {
	return &ZeroDocumentMarshaller{input, hashKey, outputs, 1}
}

// Start 不停从input接收，发送到outputs
func (m *ZeroDocumentMarshaller) Start() {
	buffer := make([]interface{}, QUEUE_GET_SIZE)
	outBuffer := make([]interface{}, QUEUE_GET_SIZE)

	for {
		n := m.input.Gets(m.hashKey, buffer)
		log.Debugf("%d docs received", n)
		nOut := 0
		for _, e := range buffer[:n] {
			if doc, ok := e.(*app.Document); ok {
				code := doc.Tag.(*zerodoc.Tag).Code
				header := &zero.ZeroHeader{
					Timestamp: proto.Uint32(doc.Timestamp),
					Sequence:  proto.Uint32(m.sequence),
					Hash:      proto.Uint32(codeHash(code)),
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
				outBuffer[nOut] = bytes
				nOut++
				m.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be []byte", doc)
			}
		}

		for i := 1; i < len(m.outputs); i++ { // 先克隆，再发送，避免在队列中被Release
			for _, b := range outBuffer[:nOut] {
				utils.PseudoCloneByteBuffer(b.(*utils.ByteBuffer))
			}
		}
		for _, q := range m.outputs {
			q.Put(outBuffer[:nOut]...)
		}
		for i := 0; i < nOut; i++ {
			outBuffer[i] = nil // 避免持有对象
		}
	}
}
