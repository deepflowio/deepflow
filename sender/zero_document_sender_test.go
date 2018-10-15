package sender

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/message/zero"
)

func TestZeroDocumentSender(t *testing.T) {
	header := &zero.ZeroHeader{
		Timestamp: proto.Uint32(0),
		Sequence:  proto.Uint32(0),
		Hash:      proto.Uint32(0),
	}
	hb, _ := proto.Marshal(header)
	inputQueue1 := queue.NewOverwriteQueue("", 1024)
	inputQueue2 := queue.NewOverwriteQueue("", 1024)
	NewZeroDocumentSenderBuilder().AddQueue(inputQueue1, inputQueue2).AddZero("127.0.0.1", 20001).AddZero("127.0.0.1", 20002).Build().Start(1024)
	testData := dupTestData()
	inputQueue1.Put(testData[0])
	inputQueue2.Put(testData[1])

	chan1 := make(chan *utils.ByteBuffer)
	chan2 := make(chan *utils.ByteBuffer)
	go receiverRoutine(len(TEST_DATA), 20001, chan1)
	go receiverRoutine(len(TEST_DATA), 20002, chan2)

	for bytes := range chan1 {
		b := bytes.Bytes()
		doc, _ := unmarshal(b[len(hb):])
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

	for bytes := range chan2 {
		b := bytes.Bytes()
		doc, _ := unmarshal(b[len(hb):])
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
