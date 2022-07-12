/*
 * Copyright (c) 2022 Yunshan Networks
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
	"fmt"
	"time"

	zmq "github.com/pebbe/zmq4"
)

// Subscriber is a wrapped ZeroMQ socket for subscribe
type Subscriber struct {
	*zmq.Socket
}

// NewSubscriber returns ZeroMQ TCP subscribe on specified ip and port
func NewSubscriber(ip string, port int, hwm int, mode ClientOrServer) (Receiver, error) {
	s, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		return nil, err
	}

	err = s.SetRcvhwm(hwm)
	if err != nil {
		return nil, err
	}

	err = s.SetRcvtimeo(time.Minute * 5)
	if err != nil {
		return nil, err
	}
	err = s.SetLinger(0)
	if err != nil {
		return nil, err
	}
	if err := s.SetIpv6(true); err != nil {
		return nil, err
	}

	if mode == CLIENT {
		err = s.Connect(fmt.Sprintf("tcp://%s:%d", ipFormat(ip), port))
	} else {
		err = s.Bind(fmt.Sprintf("tcp://%s:%d", ipFormat(ip), port))
	}
	if err != nil {
		return nil, err
	}

	s.SetSubscribe("")
	return &Subscriber{Socket: s}, nil
}

// Recv from ZeroMQ
func (s *Subscriber) Recv() ([]byte, error) {
	return s.Socket.RecvBytes(0)
}

// RecvNoBlock from ZeroMQ
func (s *Subscriber) RecvNoBlock() ([]byte, error) {
	return s.Socket.RecvBytes(zmq.DONTWAIT)
}

// Close socket
func (s *Subscriber) Close() error {
	return s.Socket.Close()
}
