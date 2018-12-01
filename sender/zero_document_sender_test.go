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
	NewZeroDocumentSenderBuilder().AddQueue(inputQueue1, 1).AddQueue(inputQueue2, 1).AddListenPorts(20001, 20002).Build().Start(1024)
	testData := dupTestData()
	inputQueue1.Put(queue.HashKey(0), testData[0])
	inputQueue2.Put(queue.HashKey(0), testData[1])

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
