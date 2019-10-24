package sender

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	ENCODE_BIND_COUNT = 16
)

type ZeroDocumentMarshaller struct {
	input    queue.QueueReader
	outputs  []queue.QueueWriter
	sequence uint64
}

// NewZeroDocumentMarshaller 从input读取app.Document，转换为pb.ZeroDocument结构，复制并推送到每一个outputs里
func NewZeroDocumentMarshaller(input queue.QueueReader, outputs ...queue.QueueWriter) *ZeroDocumentMarshaller {
	return &ZeroDocumentMarshaller{input, outputs, 1}
}

func (m *ZeroDocumentMarshaller) batchEncode(buffer []interface{}) *codec.SimpleEncoder {
	encoder := codec.AcquireSimpleEncoder()

	for _, buf := range buffer {
		if doc, ok := buf.(*app.Document); ok {
			err := zerodoc.Encode(m.sequence, doc, encoder)
			app.ReleaseDocument(doc)
			if err != nil {
				log.Warning(err)
				encoder.Reset()
				continue
			}
			m.sequence++
		} else {
			panic(fmt.Sprintf("Invalid message type %T, should be *app.Document", buf))
		}
	}

	if len(encoder.Bytes()) == 0 {
		codec.ReleaseSimpleEncoder(encoder)
		log.Infof("Batch encode null, buffer len=%d", len(buffer))
		return nil
	}
	return encoder
}

// Start 不停从input接收，发送到outputs
func (m *ZeroDocumentMarshaller) Start() {
	buffer := make([]interface{}, QUEUE_BATCH_SIZE)
	outBuffer := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := m.input.Gets(buffer)
		log.Debugf("%d docs received", n)
		nOut := 0
		for i := 0; i < n; i += ENCODE_BIND_COUNT {
			encoder := m.batchEncode(buffer[i:utils.Min(i+ENCODE_BIND_COUNT, n)])
			if encoder != nil {
				outBuffer[nOut] = encoder
				nOut++
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
