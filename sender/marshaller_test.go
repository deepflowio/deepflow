package sender

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const TEST_QUEUES = 10

func TestMarshaller(t *testing.T) {
	inputQueue := queue.NewOverwriteQueues("", 1, 1024)
	outputQueues := make([]queue.QueueReader, TEST_QUEUES)
	outputWriters := make([]queue.QueueWriter, TEST_QUEUES)
	for i := 0; i < TEST_QUEUES; i++ {
		q := queue.NewOverwriteQueue("", 1024)
		outputQueues[i] = q
		outputWriters[i] = q
	}
	go NewZeroDocumentMarshaller(inputQueue, queue.HashKey(0), outputWriters...).Start()

	inputQueue.Put(queue.HashKey(0), dupTestData()...)
	for _, q := range outputQueues {
		bytes := q.Get().(*codec.SimpleEncoder)
		newDoc, _ := decode(bytes.Bytes())

		doc := TEST_DATA[0].(*app.Document)

		if !documentEqual(doc, newDoc) {
			t.Error("文档不一致")
		}
	}
}
