package zmq

import "io"

type Sender interface {
	Send(b []byte) (n int, err error)
	SendNoBlock(b []byte) (n int, err error)
	io.Closer
}

type Receiver interface {
	Recv() ([]byte, error)
	RecvNoBlock() ([]byte, error)
	io.Closer
}
