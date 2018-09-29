package sender

import (
	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

type FlowSender struct {
	input queue.QueueReader
	*ZMQBytePusher
	sequence uint32
}

func NewFlowSender(input queue.QueueReader, ip string, port uint16, zmqHWM int) *FlowSender {
	return &FlowSender{input, NewZMQBytePusher(ip, port, zmqHWM), 1}
}

// filter 如果流不被存储，返回true
func (s *FlowSender) filter(flow *datatype.TaggedFlow) bool {
	if flow.PolicyData.ActionList&datatype.ACTION_FLOW_STORE == 0 {
		return true
	}
	return false
}

func (s *FlowSender) run() {
	bytes := utils.AcquireByteBuffer() // never release
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
				bytes.Reset()
				if _, err := header.MarshalTo(bytes.Use(header.Size())); err != nil {
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				if err := datatype.MarshalFlow(flow, bytes); err != nil {
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				s.ZMQBytePusher.Send(bytes.Bytes())
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
