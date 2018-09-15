package zmq

import (
	"testing"
	"time"
)

const SOCKET_RETRIES = 5

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
	var err error
	var pub Sender
	for i := 0; i < SOCKET_RETRIES; i++ {
		pub, err = NewPublisher("*", 12345, 10000, SERVER)
		if err == nil {
			break
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
	var sub Receiver
	for i := 0; i < SOCKET_RETRIES; i++ {
		sub, err = NewSubscriber("127.0.0.1", 12345, 1000000, CLIENT)
		if err == nil {
			break
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
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
	var err error
	var push Sender
	for i := 0; i < SOCKET_RETRIES; i++ {
		push, err = NewPusher("*", 12345, 10000, SERVER)
		if err == nil {
			break
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
	var pull Receiver
	for i := 0; i < SOCKET_RETRIES; i++ {
		pull, err = NewPuller("127.0.0.1", 12345, 1000000, time.Minute, CLIENT)
		if err == nil {
			break
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
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
