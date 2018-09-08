package sender

import (
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type FlowSender struct {
	input queue.QueueReader
	*ZMQBytePusher
}

func NewFlowSender(input queue.QueueReader, ip string, port int) *FlowSender {
	return &FlowSender{input, NewZMQBytePusher(ip, port)}
}

// filter 如果流不被存储，返回true
func (s *FlowSender) filter(flow *datatype.TaggedFlow) bool {
	if flow.PolicyData.ActionList&datatype.ACTION_FLOW_STORE == 0 {
		return true
	}
	return false
}

func (s *FlowSender) run() {
	buffer := make([]interface{}, QUEUE_GET_SIZE)
	for {
		n := s.input.Gets(buffer)
		log.Debugf("%d flows received", n)
		for _, e := range buffer[:n] {
			if flow, ok := e.(*datatype.TaggedFlow); ok {
				if s.filter(flow) {
					continue
				}
				bin, err := datatype.MarshalFlow(flow)
				if err != nil {
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				s.ZMQBytePusher.Send(bin)
			} else {
				log.Warningf("Invalid message type %T, should be *TaggedFlow", flow)
			}
		}
	}
}

func (s *FlowSender) Start() {
	go s.run()
}
