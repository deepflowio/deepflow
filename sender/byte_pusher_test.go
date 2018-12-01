package sender

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

var data = [][]byte{
	[]byte{1, 2, 3, 4, 5},
	[]byte{2, 3, 4, 5, 6},
	[]byte{3, 4, 5, 6, 7},
	[]byte{4, 5, 6, 7, 8},
}

func TestBytePusher(t *testing.T) {
	output := make(chan *codec.SimpleEncoder)
	q := queue.NewOverwriteQueue("", 1024)
	for _, d := range data {
		encoder := codec.AcquireSimpleEncoder()
		encoder.WriteRawString(string(d))
		q.Put(encoder)
	}
	go receiverRoutine(len(data), "127.0.0.1", 12345, output)
	go senderRoutine(q)
	for _, d := range data {
		encoder := <-output
		b := encoder.Bytes()
		for i := 0; i < len(b); i++ {
			if b[i] != d[i] {
				t.Error("结果不一致")
				break
			}
		}
		codec.ReleaseSimpleEncoder(encoder)
	}
}

func senderRoutine(q queue.QueueReader) {
	sender := NewZMQBytePusher("*", 12345, 1000)
	sender.QueueForward(q)
}
