package messenger

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

type Receiver struct {
	zmq.Receiver
}

func NewReceiver(r zmq.Receiver) *Receiver {
	return &Receiver{r}
}

func (r *Receiver) Receive() (*app.Document, error) {
	b, err := r.Receiver.Recv()
	if err != nil {
		return nil, err
	}
	doc, err := Unmarshal(b)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func (r *Receiver) ReceiveNoBlock() (*app.Document, error) {
	b, err := r.Receiver.RecvNoBlock()
	if err != nil {
		return nil, err
	}
	doc, err := Unmarshal(b)
	if err != nil {
		return nil, err
	}
	return doc, nil
}
