package sender

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func TestZeroDocumentSender(t *testing.T) {
	inputQueue1 := queue.NewOverwriteQueues("", 1, 1024)
	inputQueue2 := queue.NewOverwriteQueues("", 1, 1024)
	readerQueue1 := []queue.QueueReader{inputQueue1[0]}
	readerQueue2 := []queue.QueueReader{inputQueue2[0]}
	writerQueue1 := []queue.QueueWriter{inputQueue1[0]}
	writerQueue2 := []queue.QueueWriter{inputQueue2[0]}
	NewZeroDocumentSenderBuilder().AddQueue(readerQueue1).AddQueue(readerQueue2).AddListenPorts(20001, 20002).Build().Start(1024)
	testData := dupTestData()
	writerQueue1[0].Put(testData[0])
	writerQueue2[0].Put(testData[1])

	chan1 := make(chan *codec.SimpleEncoder)
	chan2 := make(chan *codec.SimpleEncoder)
	go receiverRoutine(len(TEST_DATA), "127.0.0.1", 20001, chan1)
	go receiverRoutine(len(TEST_DATA), "127.0.0.1", 20002, chan2)

	for encoder := range chan1 {
		b := encoder.Bytes()
		doc, _ := decode(b)
		hasEqual := false
		for _, data := range TEST_DATA {
			if documentEqual(doc, data.(*app.Document)) {
				hasEqual = true
				break
			}
		}
		if !hasEqual {
			t.Error("找不到对应文档", doc)
		}
	}

	for encoder := range chan2 {
		b := encoder.Bytes()
		doc, _ := decode(b)
		hasEqual := false
		for _, data := range TEST_DATA {
			if documentEqual(doc, data.(*app.Document)) {
				hasEqual = true
				break
			}
		}
		if !hasEqual {
			t.Error("找不到对应文档", doc)
		}
	}
}
