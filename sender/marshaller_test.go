package sender

import (
	"testing"

	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const TEST_QUEUES = 10

func TestMarshaller(t *testing.T) {
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
		newDoc, _ := messenger.Unmarshal(q.Get().([]byte))

		doc := TEST_DATA[0].(*api.Document)

		if !documentEqual(doc, newDoc) {
			t.Error("文档不一致")
		}
	}
}
