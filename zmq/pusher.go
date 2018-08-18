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
	s.SetSndhwm(hwm)
	s.SetSndtimeo(time.Minute * 5)
	s.SetLinger(0)
	if mode == CLIENT {
		s.Connect(fmt.Sprintf("tcp://%s:%d", ip, port))
	} else {
		s.Bind(fmt.Sprintf("tcp://%s:%d", ip, port))
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
