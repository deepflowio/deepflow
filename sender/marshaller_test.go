package sender

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/message/zero"
)

const TEST_QUEUES = 10

func TestMarshaller(t *testing.T) {
	header := &zero.ZeroHeader{
		Timestamp: proto.Uint32(0),
		Sequence:  proto.Uint32(0),
		Hash:      proto.Uint32(0),
	}
	b, _ := proto.Marshal(header)
	inputQueue := queue.NewOverwriteQueue("", 1024)
	outputQueues := make([]queue.Queue, TEST_QUEUES)
	outputWriters := make([]queue.QueueWriter, TEST_QUEUES)
	for i := 0; i < TEST_QUEUES; i++ {
		outputQueues[i] = queue.NewOverwriteQueue("", 1024)
		outputWriters[i] = outputQueues[i]
	}
	go NewZeroDocumentMarshaller(inputQueue, outputWriters...).Start()

	inputQueue.Put(TEST_DATA...)
	for _, q := range outputQueues {
		bytes := q.Get().(*utils.ByteBuffer)
		newDoc, _ := messenger.Unmarshal(bytes.Bytes()[len(b):])

		doc := TEST_DATA[0].(*app.Document)

		if !documentEqual(doc, newDoc) {
			t.Error("文档不一致")
		}
	}
}
