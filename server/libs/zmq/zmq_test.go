/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
