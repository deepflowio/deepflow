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
func NewSubscriber(ip string, port int, hwm int) (Receiver, error) {
	s, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		return nil, err
	}
	s.SetRcvhwm(hwm)
	s.SetRcvtimeo(time.Minute * 5)
	s.SetLinger(0)
	s.Connect(fmt.Sprintf("tcp://%s:%d", ip, port))
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
