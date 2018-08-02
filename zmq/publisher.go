package zmq

import (
	"fmt"
	"time"

	zmq "github.com/pebbe/zmq4"
)

// Publisher is a wrapped ZeroMQ socket for publish
type Publisher struct {
	*zmq.Socket
}

// NewPublisher returns ZeroMQ TCP publisher on specified port
func NewPublisher(port int, hwm int) (*Publisher, error) {
	s, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		return nil, err
	}
	s.SetSndhwm(hwm)
	s.SetSndtimeo(time.Minute * 5)
	s.SetLinger(0)
	s.Bind(fmt.Sprintf("tcp://*:%d", port))
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
func (p *Publisher) Close() {
	p.Socket.Close()
}
