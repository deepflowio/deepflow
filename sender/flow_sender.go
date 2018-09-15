package sender

import (
	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

type FlowSender struct {
	input queue.QueueReader
	*ZMQBytePusher
	sequence uint32
}

func NewFlowSender(input queue.QueueReader, ip string, port int) *FlowSender {
	return &FlowSender{input, NewZMQBytePusher(ip, port), 1}
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
				header := &pb.StreamHeader{
					Timestamp: proto.Uint32(uint32(flow.StartTime.Seconds())),
					Sequence:  proto.Uint32(s.sequence),
					Action:    proto.Uint32(uint32(flow.PolicyData.ActionList)),
				}
				message, err := proto.Marshal(header)
				if err != nil {
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				bin, err := datatype.MarshalFlow(flow)
				if err != nil {
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				message = append(message, bin...)
				s.ZMQBytePusher.Send(message)
				s.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be *TaggedFlow", flow)
			}
		}
	}
}

func (s *FlowSender) Start() {
	go s.run()
}
