package zmq

import (
	"math/rand"
	"time"

	"testing"
)

const (
	SOCKET_RETRIES = 5
	PORT_MIN       = 1024
	PORT_MAX       = 65536
)

func senderRoutine(t *testing.T, b []byte, ch chan int, p Sender) {
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
	t.Log("Read")
	d, _ := s.Recv()
	close(ch)
	out <- d
}

func TestPubSub(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	s := [...]byte{1, 2, 3}
	c := make(chan int)
	out := make(chan []byte)
	var err error
	var pub Sender
	var port int
	for i := 0; i < SOCKET_RETRIES; i++ {
		port = rand.Intn(PORT_MAX-PORT_MIN) + PORT_MIN
		pub, err = NewPublisher("*", port, 10000, SERVER)
		if err == nil {
			break
		} else {
			t.Log(err)
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
	var sub Receiver
	for i := 0; i < SOCKET_RETRIES; i++ {
		sub, err = NewSubscriber("127.0.0.1", port, 1000000, CLIENT)
		if err == nil {
			break
		} else {
			t.Log(err)
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
	pub.Close()
	sub.Close()
}

func TestPushPull(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	s := [...]byte{1, 2, 3}
	c := make(chan int)
	out := make(chan []byte)
	var err error
	var push Sender
	var port int
	for i := 0; i < SOCKET_RETRIES; i++ {
		port = rand.Intn(PORT_MAX-PORT_MIN) + PORT_MIN
		push, err = NewPusher("*", port, 10000, SERVER)
		if err == nil {
			break
		} else {
			t.Log(err)
		}
		if i == SOCKET_RETRIES-1 {
			t.FailNow()
		}
	}
	var pull Receiver
	for i := 0; i < SOCKET_RETRIES; i++ {
		pull, err = NewPuller("127.0.0.1", port, 1000000, time.Minute, CLIENT)
		if err == nil {
			break
		} else {
			t.Log(err)
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
	push.Close()
	pull.Close()
}
