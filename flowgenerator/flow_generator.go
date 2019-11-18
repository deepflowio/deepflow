package flowgenerator

import (
	"time"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
)

var log = logging.MustGetLogger("flowgenerator")

func (f *FlowGenerator) processPackets(processBuffer, captureBuffer []interface{}) {
	captureBuffer = captureBuffer[:0]

	for i, e := range processBuffer {
		if e == nil { // flush indicator
			f.flowMap.InjectFlushTicker(0)
			continue
		}
		processBuffer[i] = nil

		block := e.(*MetaPacketBlock)
		f.flowMap.InjectMetaPacket(block)

		for j := uint8(0); j < block.Count; j++ {
			if block.Metas[j].PolicyData != nil { // 不在时间窗口的Packet不会触发策略匹配
				block.ActionFlags |= block.Metas[j].PolicyData.ActionFlags
			}
		}
		if block.ActionFlags&ACTION_PACKET_CAPTURING != 0 {
			captureBuffer = append(captureBuffer, block)
		} else {
			ReleaseMetaPacketBlock(block)
		}
	}

	if len(captureBuffer) > 0 {
		f.pcapAppQueue.Put(captureBuffer...)
		captureBuffer = captureBuffer[:0]
	}
}

func (f *FlowGenerator) handlePackets() {
	inputQueue := f.inputQueue
	recvBuffer := make([]interface{}, QUEUE_BATCH_SIZE)
	captureBuffer := make([]interface{}, 0, QUEUE_BATCH_SIZE)
	gotSize := 0

	for f.running {
		gotSize = inputQueue.Gets(recvBuffer)
		f.processPackets(recvBuffer[:gotSize], captureBuffer)
	}
}

func (f *FlowGenerator) Start() {
	if !f.running {
		f.running = true
		go f.handlePackets()
	}
	log.Infof("flow generator %d started", f.index)
}

func (f *FlowGenerator) Stop() {
	if f.running {
		f.running = false
	}
	log.Infof("flow generator %d stopped", f.index)
}

// create a new flow generator
func New(policyGetter PolicyGetter, inputQueue QueueReader, pcapAppQueue, packetAppQueue, flowAppQueue QueueWriter, flowLimitNum, index int, flushInterval time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		flowMap: NewFlowMap(
			int(hashMapSize), flowLimitNum, index,
			maxTimeout, packetDelay, flushInterval,
			packetAppQueue, flowAppQueue, policyGetter),
		inputQueue:   inputQueue,
		pcapAppQueue: pcapAppQueue,
		index:        index,
	}
	return flowGenerator
}
