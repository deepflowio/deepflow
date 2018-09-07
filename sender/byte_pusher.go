package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

type ZMQBytePusher struct {
	ip   string
	port int
	zmq.Sender
}

// NewZMQBytePusher 包装zmq pusher
func NewZMQBytePusher(ip string, port int) *ZMQBytePusher {
	return &ZMQBytePusher{ip: ip, port: port}
}

// Send 向创建的zmq socket阻塞发送数据
func (s *ZMQBytePusher) Send(b []byte) {
	if s.Sender == nil {
		sender, err := zmq.NewPusher(s.ip, s.port, DEFAULT_HWM, zmq.CLIENT)
		if err != nil {
			log.Warningf("NewPusher() error: %s\n", err)
			s.Sender = nil
			return
		}
		s.Sender = sender
	}
	n, err := s.Sender.Send(b)
	if err != nil {
		log.Warningf("Sender has error, will reconnect: %s\n", err)
		s.Sender = nil
		return
	}
	log.Debugf("Sent %d bytes", n)
}

// QueueForward 不断读取q中的数据，并通过创建的zmq socket向外发送
func (s *ZMQBytePusher) QueueForward(q queue.QueueReader) {
	buffer := make([]interface{}, QUEUE_GET_SIZE)
	for {
		n := q.Gets(buffer)
		log.Debugf("%d byte arrays received", n)
		for i := 0; i < n; i++ {
			if b, ok := buffer[i].([]byte); ok {
				s.Send(b)
			} else {
				log.Warningf("Invalid message type %T, should be []byte", b)
			}
		}
	}
}
