package sender

import (
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/protobuf"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

type FlowSender struct {
	inputs         []queue.QueueReader
	sinkWriter     queue.QueueWriter
	sinkReader     queue.QueueReader
	throttleQueues []*ThrottlingQueue
	*ZMQBytePusher
	sequence uint32
}

func NewFlowSender(inputs []queue.QueueReader, sinkWriter queue.QueueWriter, sinkReader queue.QueueReader, ip string, port uint16, throttle, zmqHWM int) *FlowSender {
	s := &FlowSender{
		inputs:         inputs,
		sinkWriter:     sinkWriter,
		sinkReader:     sinkReader,
		throttleQueues: make([]*ThrottlingQueue, len(inputs)),
		ZMQBytePusher:  NewZMQBytePusher(ip, port, zmqHWM),
		sequence:       1,
	}
	for i := range s.throttleQueues {
		s.throttleQueues[i] = NewThrottlingQueue(throttle, sinkWriter)
	}
	return s
}

// filter 如果流不被存储，返回true
// FIXME: 流为IPv6流量，返回true
func (s *FlowSender) filter(flow *datatype.TaggedFlow) bool {
	return flow.PolicyData.ActionFlags&datatype.ACTION_FLOW_STORING == 0 || flow.EthType == layers.EthernetTypeIPv6
}

func (s *FlowSender) receive(input queue.QueueReader, throttleQueue *ThrottlingQueue) {
	inputBuffer := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := input.Gets(inputBuffer)
		for _, e := range inputBuffer[:n] {
			if flow, ok := e.(*datatype.TaggedFlow); ok {
				if s.filter(flow) {
					datatype.ReleaseTaggedFlow(flow)
					continue
				}
				throttleQueue.Send(flow)
			} else {
				log.Warningf("Invalid message type %T, should be *TaggedFlow", e)
			}
		}
	}
}

func (s *FlowSender) send() {
	buffer := make([]interface{}, QUEUE_BATCH_SIZE)
	bytes := utils.AcquireByteBuffer()

	for {
		n := s.sinkReader.Gets(buffer)
		for _, e := range buffer[:n] {
			if flow, ok := e.(*datatype.TaggedFlow); ok {
				header := &pb.StreamHeader{
					Timestamp:   proto.Uint32(uint32(flow.StartTime.Seconds())),
					Sequence:    proto.Uint32(s.sequence),
					ActionFlags: proto.Uint32(uint32(flow.PolicyData.ActionFlags)),
				}
				bytes.Reset()
				if _, err := header.MarshalTo(bytes.Use(header.Size())); err != nil {
					datatype.ReleaseTaggedFlow(flow)
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				if err := protobuf.MarshalFlow(flow, bytes); err != nil {
					datatype.ReleaseTaggedFlow(flow)
					log.Warningf("Marshalling flow failed: %s", err)
					continue
				}
				datatype.ReleaseTaggedFlow(flow)
				s.ZMQBytePusher.Send(bytes.Bytes())
				s.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be *TaggedFlow", e)
			}
		}
	}
}

func (s *FlowSender) Start() {
	go s.send()
	for i := 0; i < len(s.inputs); i++ {
		go s.receive(s.inputs[i], s.throttleQueues[i])
	}
}
