package messenger

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

type Sender struct {
	zmq.Sender
}

func NewSender(s zmq.Sender) *Sender {
	return &Sender{s}
}

// zero send to alarm
func (s *Sender) SlowSend(doc *app.Document, bytes *utils.ByteBuffer) error {
	if err := Marshal(doc, bytes); err != nil {
		return err
	}
	n, err := s.Sender.Send(bytes.Bytes())
	if err != nil {
		return err
	}
	if n != len(bytes.Bytes()) {
		return fmt.Errorf("Partial message sent, %d in %d bytes", n, len(bytes.Bytes()))
	}
	return nil
}

// zero send to alarm
func (s *Sender) SlowSendNoBlock(doc *app.Document, bytes *utils.ByteBuffer) error {
	if err := Marshal(doc, bytes); err != nil {
		return err
	}
	n, err := s.Sender.SendNoBlock(bytes.Bytes())
	if err != nil {
		return err
	}
	if n != len(bytes.Bytes()) {
		return fmt.Errorf("Partial message sent, %d in %d bytes", n, len(bytes.Bytes()))
	}
	return nil
}
