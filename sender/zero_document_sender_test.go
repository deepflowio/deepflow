package sender

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/messenger"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func TestZeroDocumentSender(t *testing.T) {
	inputQueue1 := queue.NewOverwriteQueue("", 1024)
	inputQueue2 := queue.NewOverwriteQueue("", 1024)
	NewZeroDocumentSenderBuilder().AddQueue(inputQueue1, inputQueue2).AddZero("127.0.0.1", 20001).AddZero("127.0.0.1", 20002).Build().Start()
	inputQueue1.Put(TEST_DATA[0])
	inputQueue2.Put(TEST_DATA[1])

	chan1 := make(chan []byte)
	chan2 := make(chan []byte)
	go receiverRoutine(len(TEST_DATA), 20001, chan1)
	go receiverRoutine(len(TEST_DATA), 20002, chan2)

	for b := range chan1 {
		doc, _ := messenger.Unmarshal(b)
		hasEqual := false
		for _, data := range TEST_DATA {
			if documentEqual(doc, data.(*app.Document)) {
				hasEqual = true
				break
			}
		}
		if !hasEqual {
			t.Error("找不到对应文档")
		}
	}

	for b := range chan2 {
		doc, _ := messenger.Unmarshal(b)
		hasEqual := false
		for _, data := range TEST_DATA {
			if documentEqual(doc, data.(*app.Document)) {
				hasEqual = true
				break
			}
		}
		if !hasEqual {
			t.Error("找不到对应文档")
		}
	}
}
