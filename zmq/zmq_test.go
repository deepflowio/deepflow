package zmq

import (
	"testing"
	"time"
)

func senderRoutine(t *testing.T, b []byte, ch chan int, p Sender) {
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
}

func receiverRoutine(t *testing.T, ch chan int, out chan []byte, s Receiver) {
	defer s.Close()
	t.Log("Read")
	d, _ := s.Recv()
	ch <- 1
	out <- d
}

func TestPubSub(t *testing.T) {
	s := [...]byte{1, 2, 3}
	c := make(chan int)
	out := make(chan []byte)
	pub, _ := NewPublisher("*", 12345, 10000, SERVER)
	sub, _ := NewSubscriber("127.0.0.1", 12345, 1000000, CLIENT)
	go senderRoutine(t, s[:], c, pub)
	go receiverRoutine(t, c, out, sub)
	s2 := <-out
	for i := range s {
		if s[i] != s2[i] {
			t.Error("发送和接收不一致")
			break
		}
	}
}

func TestPushPull(t *testing.T) {
	s := [...]byte{1, 2, 3}
	c := make(chan int)
	out := make(chan []byte)
	push, _ := NewPusher("*", 12345, 10000, SERVER)
	pull, _ := NewPuller("127.0.0.1", 12345, 1000000, CLIENT)
	go senderRoutine(t, s[:], c, push)
	go receiverRoutine(t, c, out, pull)
	s2 := <-out
	for i := range s {
		if s[i] != s2[i] {
			t.Error("发送和接收不一致")
			break
		}
	}
}
