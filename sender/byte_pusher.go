package sender

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

type ZMQBytePusher struct {
	zmq.Sender

	ip     string
	port   uint16
	zmqHWM int
}

// NewZMQBytePusher 包装zmq pusher
func NewZMQBytePusher(ip string, port uint16, zmqHWM int) *ZMQBytePusher {
	return &ZMQBytePusher{ip: ip, port: port, zmqHWM: zmqHWM}
}

// Send 向创建的zmq socket阻塞发送数据
func (s *ZMQBytePusher) Send(b []byte) {
	if s.Sender == nil {
		var err error
		if s.ip == "" || s.ip == "*" {
			s.Sender, err = zmq.NewPusher("*", int(s.port), s.zmqHWM, zmq.SERVER)
		} else {
			s.Sender, err = zmq.NewPusher(s.ip, int(s.port), s.zmqHWM, zmq.CLIENT)
		}
		if err != nil {
			log.Warningf("NewPusher(%s:%d) error: %s\n", s.ip, s.port, err)
			time.Sleep(10 * time.Second)
			s.Sender = nil
			return
		}
	}
	_, err := s.Sender.Send(b)
	if err != nil {
		if err.Error() == "resource temporarily unavailable" {
			return
		}
		log.Warningf("Sender(%s:%d) has error, will reconnect: %s\n", s.ip, s.port, err)
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
		log.Debugf("%d byte arrays received", n)
		for i := 0; i < n; i++ {
			if encoder, ok := buffer[i].(*codec.SimpleEncoder); ok {
				s.Send(encoder.Bytes())
				codec.ReleaseSimpleEncoder(encoder)
			} else {
				log.Warningf("Invalid message type %T, should be *codec.SimpleEncoder", encoder)
			}
		}
	}
}
