package zmq

import (
	"testing"
	"time"
)

func TestPubSub(t *testing.T) {
	s := [...]byte{1, 2, 3}
	c := make(chan int)
	out := make(chan []byte)
	go func(b []byte, ch chan int) {
		p, _ := NewPublisher(12345, 1000000)
		defer p.Close()
		t.Log("Starts to send")
		for {
			select {
			case <-ch:
				t.Log("Over and out")
				return
			default:
				t.Log("Write")
				p.Send(b)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}(s[:], c)
	go func(ch chan int, out chan []byte) {
		s, _ := NewSubscriber("127.0.0.1", 12345, 1000000)
		defer s.Close()
		t.Log("Read")
		d, _ := s.Recv()
		ch <- 1
		out <- d
	}(c, out)
	s2 := <-out
	for i := range s {
		if s[i] != s2[i] {
			t.Error("发送和接收不一致")
			break
		}
	}
}
