package sender

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

var data = []interface{}{
	[]byte{1, 2, 3, 4, 5},
	[]byte{2, 3, 4, 5, 6},
	[]byte{3, 4, 5, 6, 7},
	[]byte{4, 5, 6, 7, 8},
}

func TestBytePusher(t *testing.T) {
	output := make(chan []byte)
	q := queue.NewOverwriteQueue("", 1024)
	q.Put(data...)
	go receiverRoutine(len(data), 12345, output)
	go senderRoutine(q)
	for _, rawData := range data {
		d := rawData.([]byte)
		b := <-output
		size := len(b)
		if size > len(d) {
			size = len(d)
		}
		for i := 0; i < size; i++ {
			if b[i] != d[i] {
				t.Error("结果不一致")
				break
			}
		}
	}
}

func senderRoutine(q queue.Queue) {
	sender := NewZMQBytePusher("127.0.0.1", 12345)
	sender.QueueForward(q)
}
