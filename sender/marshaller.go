package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
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
				encoder := codec.AcquireSimpleEncoder()
				err := messenger.Encode(m.sequence, codeHash(code), doc, encoder)
				app.ReleaseDocument(doc)
				if err != nil {
					codec.ReleaseSimpleEncoder(encoder)
					log.Warning(err)
					continue
				}
				outBuffer[nOut] = encoder
				nOut++
				m.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be []byte", doc)
			}
		}

		for i := 1; i < len(m.outputs); i++ { // 先克隆，再发送，避免在队列中被Release
			for _, b := range outBuffer[:nOut] {
				codec.PseudoCloneSimpleEncoder(b.(*codec.SimpleEncoder))
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
