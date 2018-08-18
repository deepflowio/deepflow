package zmq

import (
	"fmt"
	"time"

	zmq "github.com/pebbe/zmq4"
)

// Puller is a wrapped ZeroMQ socket for subscribe
type Puller struct {
	*zmq.Socket
}

// NewPuller returns ZeroMQ TCP subscribe on specified ip and port
func NewPuller(ip string, port int, hwm int, mode ClientOrServer) (Receiver, error) {
	s, err := zmq.NewSocket(zmq.PULL)
	if err != nil {
		return nil, err
	}
	s.SetRcvhwm(hwm)
	s.SetRcvtimeo(time.Minute * 5)
	s.SetLinger(0)
	if mode == CLIENT {
		s.Connect(fmt.Sprintf("tcp://%s:%d", ip, port))
	} else {
		s.Bind(fmt.Sprintf("tcp://%s:%d", ip, port))
	}
	return &Puller{Socket: s}, nil
}

// Recv from ZeroMQ
func (s *Puller) Recv() ([]byte, error) {
	return s.Socket.RecvBytes(0)
}

// RecvNoBlock from ZeroMQ
func (s *Puller) RecvNoBlock() ([]byte, error) {
	return s.Socket.RecvBytes(zmq.DONTWAIT)
}

// Close socket
func (p *Puller) Close() error {
	return p.Socket.Close()
}
