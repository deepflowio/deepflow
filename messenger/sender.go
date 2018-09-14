package messenger

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

type Sender struct {
	zmq.Sender
}

func NewSender(s zmq.Sender) *Sender {
	return &Sender{s}
}

func (s *Sender) Send(doc *app.Document) error {
	b, err := Marshal(doc)
	if err != nil {
		return err
	}
	n, err := s.Sender.Send(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("Partial message sent, %d in %d bytes", n, len(b))
	}

	return nil
}

func (s *Sender) SendNoBlock(doc *app.Document) error {
	b, err := Marshal(doc)
	if err != nil {
		return err
	}

	n, err := s.Sender.SendNoBlock(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("Partial message sent, %d in %d bytes", n, len(b))
	}
	return nil
}
