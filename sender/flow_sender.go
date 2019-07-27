package sender

import (
	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/protobuf"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

type FlowSender struct {
	inputs     []queue.QueueReader
	sinkWriter queue.QueueWriter
	sinkReader queue.QueueReader
	*ZMQBytePusher
	sequence uint32
}

func NewFlowSender(inputs []queue.QueueReader, sinkWriter queue.QueueWriter, sinkReader queue.QueueReader, ip string, port uint16, zmqHWM int) *FlowSender {
	return &FlowSender{inputs, sinkWriter, sinkReader, NewZMQBytePusher(ip, port, zmqHWM), 1}
}

// filter 如果流不被存储，返回true
func (s *FlowSender) filter(flow *datatype.TaggedFlow) bool {
	return flow.PolicyData.ActionFlags&datatype.ACTION_FLOW_STORING == 0
}

func (s *FlowSender) receive(input queue.QueueReader) {
	bytes := utils.AcquireByteBuffer()
	inputBuffer := make([]interface{}, QUEUE_BATCH_SIZE)
	sinkBuffer := make([]interface{}, 0, QUEUE_BATCH_SIZE)

	for {
		n := input.Gets(inputBuffer)
		for _, e := range inputBuffer[:n] {
			if flow, ok := e.(*datatype.TaggedFlow); ok {
				if s.filter(flow) {
					datatype.ReleaseTaggedFlow(flow)
					continue
				}
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
				sinkBuffer = append(sinkBuffer, bytes)

				bytes = utils.AcquireByteBuffer()
				s.sequence++
			} else {
				log.Warningf("Invalid message type %T, should be *TaggedFlow", e)
			}
		}

		if len(sinkBuffer) > 0 {
			s.sinkWriter.Put(sinkBuffer...)
			sinkBuffer = sinkBuffer[:0]
		}
	}
}

func (s *FlowSender) send() {
	buffer := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := s.sinkReader.Gets(buffer)
		for _, e := range buffer[:n] {
			if bytes, ok := e.(*utils.ByteBuffer); ok {
				s.ZMQBytePusher.Send(bytes.Bytes())
				utils.ReleaseByteBuffer(bytes)
			} else {
				log.Warningf("Invalid message type %T, should be *utils.ByteBuffer", e)
			}
		}
	}
}

func (s *FlowSender) Start() {
	go s.send()
	for i := 0; i < len(s.inputs); i++ {
		go s.receive(s.inputs[i])
	}
}
