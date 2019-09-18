package mapreduce

import (
	"reflect"
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/app/flow"
	"gitlab.x.lan/yunshan/droplet/app/flowtype"
	"gitlab.x.lan/yunshan/droplet/app/fps"
	"gitlab.x.lan/yunshan/droplet/app/geo"
	"gitlab.x.lan/yunshan/droplet/app/logusage"
	"gitlab.x.lan/yunshan/droplet/app/perf"
)

const (
	perfSlots = 2
)

const GEO_FILE_LOCATION = "/usr/share/droplet/ip_info_mini.json"

func NewFlowMapProcess(
	outputs []queue.QueueWriter, inputs []queue.QueueReader,
	docsInBuffer, windowSize, windowMoveMargin int,
) *FlowHandler {
	return NewFlowHandler([]app.FlowProcessor{
		fps.NewProcessor(),
		flow.NewProcessor(),
		perf.NewProcessor(),
		geo.NewProcessor(GEO_FILE_LOCATION),
		flowtype.NewProcessor(),
		logusage.NewProcessor(),
	}, outputs, inputs, docsInBuffer, windowSize, windowMoveMargin)
}

type FlowHandler struct {
	numberOfApps int
	processors   []app.FlowProcessor

	flowQueues       []queue.QueueReader
	zmqAppQueues     []queue.QueueWriter
	docsInBuffer     int
	windowSize       int
	windowMoveMargin int
}

func NewFlowHandler(
	processors []app.FlowProcessor,
	outputs []queue.QueueWriter, inputs []queue.QueueReader,
	docsInBuffer, windowSize, windowMoveMargin int,
) *FlowHandler {
	return &FlowHandler{
		numberOfApps:     len(processors),
		processors:       processors,
		zmqAppQueues:     outputs,
		flowQueues:       inputs,
		docsInBuffer:     docsInBuffer,
		windowSize:       windowSize,
		windowMoveMargin: windowMoveMargin,
	}
}

type subFlowHandler struct {
	numberOfApps int
	names        []string
	processors   []app.FlowProcessor
	stashes      []Stash

	flowQueue    queue.QueueReader
	zmqAppQueues []queue.QueueWriter
	nextQueueID  uint8

	counterLatch int
	statItems    []stats.StatItem

	lastFlush        time.Duration
	handlerCounter   []HandlerCounter
	processorCounter [][]ProcessorCounter
}

func (h *FlowHandler) newSubFlowHandler(index int) *subFlowHandler {
	dupProcessors := make([]app.FlowProcessor, h.numberOfApps)
	for i, proc := range h.processors {
		elem := reflect.ValueOf(proc).Elem()
		ref := reflect.New(elem.Type())
		ref.Elem().Set(elem)
		dupProcessors[i] = ref.Interface().(app.FlowProcessor)
		dupProcessors[i].Prepare()
	}
	handler := subFlowHandler{
		numberOfApps: h.numberOfApps,
		names:        make([]string, h.numberOfApps),
		processors:   dupProcessors,
		stashes:      make([]Stash, h.numberOfApps),

		flowQueue:    h.flowQueues[index],
		zmqAppQueues: h.zmqAppQueues,
		nextQueueID:  uint8(index),

		counterLatch: 0,
		statItems:    make([]stats.StatItem, 0),

		lastFlush: time.Duration(time.Now().UnixNano()),

		handlerCounter:   make([]HandlerCounter, 2),
		processorCounter: make([][]ProcessorCounter, 2),
	}
	handler.processorCounter[0] = make([]ProcessorCounter, handler.numberOfApps)
	handler.processorCounter[1] = make([]ProcessorCounter, handler.numberOfApps)

	for i := 0; i < handler.numberOfApps; i++ {
		handler.names[i] = handler.processors[i].GetName()
		handler.stashes[i] = NewFixedStash(uint32(h.docsInBuffer), h.windowSize)
	}
	stats.RegisterCountable("flow-mapper", &handler, stats.OptionStatTags{"index": strconv.Itoa(index)})
	return &handler
}

func (h *subFlowHandler) GetCounter() interface{} {
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

func (h *subFlowHandler) Closed() bool {
	return false // FIXME: never close?
}

func (h *subFlowHandler) putToQueue(processorID int) {
	stash := h.stashes[processorID]
	docs := stash.Dump()
	for j := 0; j < len(docs); j += QUEUE_BATCH_SIZE {
		if j+QUEUE_BATCH_SIZE <= len(docs) {
			h.zmqAppQueues[h.nextQueueID&uint8(len(h.zmqAppQueues)-1)].Put(docs[j : j+QUEUE_BATCH_SIZE]...)
		} else {
			h.zmqAppQueues[h.nextQueueID&uint8(len(h.zmqAppQueues)-1)].Put(docs[j:]...)
		}
		h.nextQueueID++
	}
	h.processorCounter[h.counterLatch][processorID].emitCounter += uint64(len(docs))
	stash.Clear()
}

func (h *FlowHandler) Start() {
	for i := 0; i < len(h.flowQueues); i++ {
		go h.newSubFlowHandler(i).Process()
	}
}

func isValidFlow(flow *datatype.TaggedFlow) bool {
	startTime := flow.StartTime
	endTime := flow.EndTime

	// we give flow timestamp a tolerance with one minute
	toleranceCurTime := time.Duration(time.Now().UnixNano()) + time.Minute
	if startTime > toleranceCurTime || endTime > toleranceCurTime {
		return false
	}
	if endTime < startTime {
		return false
	}

	return true
}

func (h *subFlowHandler) Process() error {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := h.flowQueue.Gets(elements)

		// 当前时间超出窗口右边界时，上个自然分钟的数据已计算完毕，一定能将窗口滑动一次。
		epoch := uint32(time.Now().Unix())
		for i := range h.processors {
			if epoch > h.stashes[i].GetWindowRight() {
				if h.stashes[i].Size() > 0 {
					h.processorCounter[h.counterLatch][i].flushCounter++
					h.putToQueue(i)
				}
				h.stashes[i].SetTimestamp(epoch / MINUTE * MINUTE)
			}
		}

		for _, e := range elements[:n] {
			if e == nil { // FlushIndicator
				continue
			}

			flow := e.(*datatype.TaggedFlow)
			if !isValidFlow(flow) {
				datatype.ReleaseTaggedFlow(flow)
				h.handlerCounter[h.counterLatch].dropCounter++
				continue
			}

			// 统计处理的流数量
			h.handlerCounter[h.counterLatch].inputCounter++

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
					h.putToQueue(i)
				}
			}
			datatype.ReleaseTaggedFlow(flow)
		}
	}
}
