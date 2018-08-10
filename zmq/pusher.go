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
func NewPusher(port int, hwm int) (Sender, error) {
	s, err := zmq.NewSocket(zmq.PUSH)
	if err != nil {
		return nil, err
	}
	s.SetSndhwm(hwm)
	s.SetSndtimeo(time.Minute * 5)
	s.SetLinger(0)
	s.Bind(fmt.Sprintf("tcp://*:%d", port))
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
