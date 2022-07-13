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

// Pusher is a wrapped ZeroMQ socket for publish
type Pusher struct {
	*zmq.Socket
}

// NewPusher returns ZeroMQ TCP publisher on specified port
func NewPusher(ip string, port int, hwm int, mode ClientOrServer) (Sender, error) {
	s, err := zmq.NewSocket(zmq.PUSH)
	if err != nil {
		return nil, err
	}

	err = s.SetSndhwm(hwm)
	if err != nil {
		return nil, err
	}

	err = s.SetSndtimeo(time.Minute * 5)
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

	return &Pusher{Socket: s}, nil
}

// Send to ZeroMQ
func (p *Pusher) Send(b []byte) (n int, err error) {
	return p.Socket.SendBytes(b, 0)
}

// SendNoBlock to ZeroMQ
func (p *Pusher) SendNoBlock(b []byte) (n int, err error) {
	return p.Socket.SendBytes(b, zmq.DONTWAIT)
}

// Close socket
func (p *Pusher) Close() error {
	return p.Socket.Close()
}
