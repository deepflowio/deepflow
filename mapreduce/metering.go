package mapreduce

import (
	"reflect"
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/app/usage"
)

func NewMeteringMapProcess(
	zmqAppQueues []queue.QueueWriter, packetQueues []queue.QueueReader,
	docsInBuffer, windowSize, windowMoveMargin int,
) *MeteringHandler {
	return NewMeteringHandler(
		[]app.MeteringProcessor{usage.NewProcessor()}, zmqAppQueues, packetQueues,
		docsInBuffer, windowSize, windowMoveMargin)
}

type MeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor

	packetQueues     []queue.QueueReader
	zmqAppQueues     []queue.QueueWriter
	docsInBuffer     int
	windowSize       int
	windowMoveMargin int
}

func NewMeteringHandler(
	processors []app.MeteringProcessor,
	zmqAppQueues []queue.QueueWriter, packetQueues []queue.QueueReader,
	docsInBuffer, windowSize, windowMoveMargin int,
) *MeteringHandler {
	return &MeteringHandler{
		numberOfApps:     len(processors),
		processors:       processors,
		zmqAppQueues:     zmqAppQueues,
		packetQueues:     packetQueues,
		docsInBuffer:     docsInBuffer,
		windowSize:       windowSize,
		windowMoveMargin: windowMoveMargin,
	}
}

type subMeteringHandler struct {
	numberOfApps int
	names        []string
	processors   []app.MeteringProcessor
	stashes      []Stash

	packetQueue  queue.QueueReader
	zmqAppQueues []queue.QueueWriter
	nextQueueID  uint8

	lastFlush    time.Duration
	counterLatch int
	statItems    []stats.StatItem

	handlerCounter   []HandlerCounter
	processorCounter [][]ProcessorCounter
}

func (h *MeteringHandler) newSubMeteringHandler(index int) *subMeteringHandler {
	dupProcessors := make([]app.MeteringProcessor, h.numberOfApps)
	for i, proc := range h.processors {
		elem := reflect.ValueOf(proc).Elem()
		ref := reflect.New(elem.Type())
		ref.Elem().Set(elem)
		dupProcessors[i] = ref.Interface().(app.MeteringProcessor)
		dupProcessors[i].Prepare()
	}
	handler := subMeteringHandler{
		numberOfApps: h.numberOfApps,
		names:        make([]string, h.numberOfApps),
		processors:   dupProcessors,
		stashes:      make([]Stash, h.numberOfApps),

		packetQueue:  h.packetQueues[index],
		zmqAppQueues: h.zmqAppQueues,
		nextQueueID:  uint8(index),

		lastFlush: time.Duration(time.Now().UnixNano()),

		statItems: make([]stats.StatItem, 0),

		handlerCounter:   make([]HandlerCounter, 2),
		processorCounter: make([][]ProcessorCounter, 2),
	}
	handler.processorCounter[0] = make([]ProcessorCounter, handler.numberOfApps)
	handler.processorCounter[1] = make([]ProcessorCounter, handler.numberOfApps)

	for i := 0; i < handler.numberOfApps; i++ {
		handler.names[i] = handler.processors[i].GetName()
		handler.stashes[i] = NewSlidingStash(uint32(h.docsInBuffer), h.windowSize, h.windowMoveMargin)
	}
	stats.RegisterCountable("metering-mapper", &handler, stats.OptionStatTags{"index": strconv.Itoa(index)})
	return &handler
}

func (h *subMeteringHandler) GetCounter() interface{} {
	oldLatch := h.counterLatch
	if h.counterLatch == 0 {
		h.counterLatch = 1
	} else {
		h.counterLatch = 0
	}
	h.statItems = h.statItems[:0]
	h.statItems = FillStatItems(h.statItems, h.handlerCounter[oldLatch], h.names, h.processorCounter[oldLatch])
	for i := 0; i < h.numberOfApps; i++ {
		h.processorCounter[oldLatch][i] = ProcessorCounter{}
	}
	h.handlerCounter[oldLatch] = HandlerCounter{}

	return h.statItems
}

func (h *subMeteringHandler) Closed() bool {
	return false // FIXME: never close?
}

// processorID = -1 for all stash
func (h *subMeteringHandler) putToQueue(processorID int) {
	for i, stash := range h.stashes {
		if processorID >= 0 && processorID != i {
			continue
		}
		docs := stash.Dump()
		for j := 0; j < len(docs); j += QUEUE_BATCH_SIZE {
			if j+QUEUE_BATCH_SIZE <= len(docs) {
				h.zmqAppQueues[h.nextQueueID&uint8(len(h.zmqAppQueues)-1)].Put(docs[j : j+QUEUE_BATCH_SIZE]...)
			} else {
				h.zmqAppQueues[h.nextQueueID&uint8(len(h.zmqAppQueues)-1)].Put(docs[j:]...)
			}
			h.nextQueueID++
		}
		h.processorCounter[h.counterLatch][i].emitCounter += uint64(len(docs))
		stash.Clear()
	}
}

func (h *MeteringHandler) Start() {
	for i := 0; i < len(h.packetQueues); i++ {
		go h.newSubMeteringHandler(i).Process()
	}
}

func (h *subMeteringHandler) Process() error {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := h.packetQueue.Gets(elements)
		for _, e := range elements[:n] {
			if e == nil { // tick
				h.Flush(-1)
				continue
			}

			flow := e.(*datatype.TaggedFlow)
			if !isValidFlow(flow) {
				datatype.ReleaseTaggedFlow(flow)
				h.handlerCounter[h.counterLatch].dropCounter++
				continue
			}

			// 统计处理的包数量和字节数量
			flowMetricsPeerSrc := &flow.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC]
			flowMetricsPeerDst := &flow.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST]

			h.handlerCounter[h.counterLatch].inputCounter += uint64(flowMetricsPeerSrc.TickPacketCount) + uint64(flowMetricsPeerDst.TickPacketCount)
			h.handlerCounter[h.counterLatch].byteCounter += uint64(flowMetricsPeerSrc.TickByteCount) + uint64(flowMetricsPeerDst.TickByteCount)

			for i, processor := range h.processors {
				docs := processor.Process(flow, false)
				h.processorCounter[h.counterLatch][i].docCounter += uint64(len(docs))
				if uint64(len(docs)) > h.processorCounter[h.counterLatch][i].maxCounter {
					h.processorCounter[h.counterLatch][i].maxCounter = uint64(len(docs))
				}
				for {
					docs = h.stashes[i].Add(docs)
					if docs == nil {
						break
					}
					h.processorCounter[h.counterLatch][i].flushCounter++
					h.Flush(i)
				}
			}
			datatype.ReleaseTaggedFlow(flow)
		}
		if time.Duration(time.Now().UnixNano())-h.lastFlush >= FLUSH_INTERVAL {
			h.Flush(-1)
		}
	}
}

func (h *subMeteringHandler) Flush(processorID int) {
	if processorID == -1 { // 单独Flush某个processor的stash时不更新
		h.lastFlush = time.Duration(time.Now().UnixNano())
	}
	h.putToQueue(processorID)
}
