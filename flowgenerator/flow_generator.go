package flowgenerator

import (
	"time"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
)

var log = logging.MustGetLogger("flowgenerator")

func (f *FlowGenerator) processPackets(processBuffer []interface{}) {
	for i, e := range processBuffer {
		if e == nil { // flush indicator
			f.flowMap.InjectFlushTicker(toTimestamp(time.Now()))
			continue
		}

		block := e.(*MetaPacketBlock)
		f.flowMap.InjectMetaPacket(block)
		ReleaseMetaPacketBlock(block)
		processBuffer[i] = nil
	}
}

func (f *FlowGenerator) handlePackets() {
	inputQueue := f.inputQueue
	recvBuffer := make([]interface{}, QUEUE_BATCH_SIZE)
	gotSize := 0

	for f.running {
		gotSize = inputQueue.Gets(recvBuffer)
		f.processPackets(recvBuffer[:gotSize])
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
func New(inputQueue QueueReader, packetAppQueue, flowAppQueue QueueWriter, flowLimitNum, index int, flushInterval time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		flowMap:    NewFlowMap(int(hashMapSize), flowLimitNum, index, maxTimeout, packetDelay, flushInterval, packetAppQueue, flowAppQueue),
		inputQueue: inputQueue,
		index:      index,
	}
	return flowGenerator
}
