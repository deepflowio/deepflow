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
	logging "github.com/op/go-logging"
	"github.com/pebbe/zmq4"

	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("sender")

const QUEUE_GET_SIZE = 1024

type ZMQBytePusher struct {
	Sender

	ip     string
	port   uint16
	zmqHWM int
	t      zmq4.Type
}

// NewZMQBytePusher 包装zmq pusher
func NewZMQBytePusher(ip string, port uint16, zmqHWM int, t zmq4.Type) *ZMQBytePusher {
	return &ZMQBytePusher{ip: ip, port: port, zmqHWM: zmqHWM, t: t}
}

// Send 向创建的zmq socket阻塞发送数据
func (s *ZMQBytePusher) Send(b []byte) {
	if s.Sender == nil {
		if s.t == zmq4.PUSH {
			sender, err := NewPusher(s.ip, int(s.port), s.zmqHWM, CLIENT)
			if err != nil {
				log.Warningf("NewPusher() error: %s\n", err)
				s.Sender = nil
				return
			}
			s.Sender = sender
		} else if s.t == zmq4.PUB {
			sender, err := NewPublisher(s.ip, int(s.port), s.zmqHWM, SERVER)
			if err != nil {
				log.Warningf("NewPublisher() error: %s\n", err)
				s.Sender = nil
				return
			}
			s.Sender = sender
		}
	}
	_, err := s.Sender.Send(b)
	if err != nil {
		log.Warningf("Sender has error, will reconnect: %s\n", err)
		s.Sender.Close()
		s.Sender = nil
		return
	}
}

// QueueForward 不断读取q中的数据，并通过创建的zmq socket向外发送
func (s *ZMQBytePusher) QueueForward(q queue.QueueReader) {
	buffer := make([]interface{}, QUEUE_GET_SIZE)
	for {
		n := q.Gets(buffer)
		for i := 0; i < n; i++ {
			if bytes, ok := buffer[i].(*utils.ByteBuffer); ok {
				s.Send(bytes.Bytes())
				utils.ReleaseByteBuffer(bytes)
			} else {
				log.Warningf("Invalid message type %T, should be *utils.ByteBuffer", bytes)
			}
		}
	}
}
