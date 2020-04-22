package zmq

import (
	"fmt"
	"time"

	zmq "github.com/pebbe/zmq4"
)

func ipFormat(s string) string {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', '[':
			return s
		case ':':
			return "[" + s + "]"
		}
	}
	return s
}

// Publisher is a wrapped ZeroMQ socket for publish
type Publisher struct {
	*zmq.Socket
}

// NewPublisher returns ZeroMQ TCP publisher on specified port
func NewPublisher(ip string, port int, hwm int, mode ClientOrServer) (Sender, error) {
	s, err := zmq.NewSocket(zmq.PUB)
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

	return &Publisher{Socket: s}, nil
}

// Send to ZeroMQ
func (p *Publisher) Send(b []byte) (n int, err error) {
	return p.Socket.SendBytes(b, 0)
}

// SendNoBlock to ZeroMQ
func (p *Publisher) SendNoBlock(b []byte) (n int, err error) {
	return p.Socket.SendBytes(b, zmq.DONTWAIT)
}

// Close socket
func (p *Publisher) Close() error {
	return p.Socket.Close()
}
