package mapreduce

import (
	"reflect"
	"strconv"

	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/consolelog"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/flow"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/flowtype"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/fps"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/geo"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/perf"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/platform"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

const (
	perfSlots = 2
)

const GEO_FILE_LOCATION = "/usr/share/droplet/ip_info_mini.json"

func NewFlowMapProcess(output queue.QueueWriter, input queue.MultiQueueReader, inputCount int, docsInBuffer int, windowSize int) *FlowHandler {
	return NewFlowHandler([]app.FlowProcessor{
		fps.NewProcessor(),
		flow.NewProcessor(),
		perf.NewProcessor(),
		geo.NewProcessor(GEO_FILE_LOCATION),
		flowtype.NewProcessor(),
		consolelog.NewProcessor(),
		platform.NewProcessor(),
	}, output, input, inputCount, docsInBuffer, windowSize)
}

type FlowHandler struct {
	numberOfApps int
	processors   []app.FlowProcessor

	flowQueue      queue.MultiQueueReader
	flowQueueCount int
	zmqAppQueue    queue.QueueWriter
	docsInBuffer   int
	windowSize     int
}

func NewFlowHandler(processors []app.FlowProcessor, output queue.QueueWriter, inputs queue.MultiQueueReader, inputCount int, docsInBuffer int, windowSize int) *FlowHandler {
	return &FlowHandler{
		numberOfApps:   len(processors),
		processors:     processors,
		zmqAppQueue:    output,
		flowQueue:      inputs,
		flowQueueCount: inputCount,
		docsInBuffer:   docsInBuffer,
		windowSize:     windowSize,
	}
}

type subFlowHandler struct {
	numberOfApps int
	processors   []app.FlowProcessor
	stashes      []*Stash

	flowQueue   queue.MultiQueueReader
	zmqAppQueue queue.QueueWriter

	queueIndex int

	emitCounter  []uint64
	counterLatch int
	statItems    []stats.StatItem

	lastFlush time.Duration
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
		processors:   dupProcessors,
		stashes:      make([]*Stash, h.numberOfApps),

		flowQueue:   h.flowQueue,
		zmqAppQueue: h.zmqAppQueue,

		queueIndex: index,

		emitCounter:  make([]uint64, h.numberOfApps*2),
		counterLatch: 0,
		statItems:    make([]stats.StatItem, h.numberOfApps),

		lastFlush: time.Duration(time.Now().UnixNano()),
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(h.docsInBuffer, h.windowSize)
		handler.statItems[i].Name = h.processors[i].GetName()
		handler.statItems[i].StatType = stats.COUNT_TYPE
	}
	stats.RegisterCountable("flow_mapper", &handler, stats.OptionStatTags{"index": strconv.Itoa(index)})
	return &handler
}

func (f *subFlowHandler) GetCounter() interface{} {
	oldLatch := f.counterLatch
	if f.counterLatch == 0 {
		f.counterLatch = f.numberOfApps
	} else {
		f.counterLatch = 0
	}
	for i := 0; i < f.numberOfApps; i++ {
		f.statItems[i].Value = f.emitCounter[i+oldLatch]
		f.emitCounter[i+oldLatch] = 0
	}
	return f.statItems
}

func (f *subFlowHandler) putToQueue() {
	for i, stash := range f.stashes {
		docs := stash.Dump()
		for j := 0; j < len(docs); j += QUEUE_BATCH_SIZE {
			if j+QUEUE_BATCH_SIZE <= len(docs) {
				f.zmqAppQueue.Put(docs[j : j+QUEUE_BATCH_SIZE]...)
			} else {
				f.zmqAppQueue.Put(docs[j:]...)
			}
		}
		f.emitCounter[i+f.counterLatch] += uint64(len(docs))
		stash.Clear()
	}
}

func (f *FlowHandler) Start() {
	for i := 0; i < f.flowQueueCount; i++ {
		go f.newSubFlowHandler(i).Process()
	}
}

func isValidFlow(flow *datatype.TaggedFlow) bool {
	startTime := flow.StartTime
	endTime := flow.EndTime
	curTime := time.Duration(time.Now().UnixNano())

	if startTime > curTime || endTime > curTime {
		return false
	}
	if endTime > startTime+2*time.Minute {
		return false
	}
	if endTime != 0 && endTime < startTime {
		return false
	}

	currStart := flow.CurStartTime
	arr0Last := flow.FlowMetricsPeerSrc.ArrTimeLast
	arr1Last := flow.FlowMetricsPeerDst.ArrTimeLast
	rightMargin := endTime + 2*time.Minute
	times := [3]time.Duration{currStart, arr0Last, arr1Last}
	for i := 0; i < 3; i++ {
		if times[i] > rightMargin || times[i] > curTime {
			return false
		}
	}
	return true
}

func (f *subFlowHandler) Process() error {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := f.flowQueue.Gets(queue.HashKey(f.queueIndex), elements)
		for _, e := range elements[:n] {
			if e == nil {
				f.Flush()
				continue
			}

			flow := e.(*datatype.TaggedFlow)
			if !isValidFlow(flow) {
				log.Warning("flow timestamp incorrect and dropped")
				continue
			}

			for i, processor := range f.processors {
				docs := processor.Process(flow, false)
				for {
					docs = f.stashes[i].Add(docs)
					if docs == nil {
						break
					}
					f.Flush()
				}
			}
			datatype.ReleaseTaggedFlow(flow)
		}
		if time.Duration(time.Now().UnixNano())-f.lastFlush >= FLUSH_INTERVAL {
			f.Flush()
		}
	}
}

func (f *subFlowHandler) Flush() {
	f.lastFlush = time.Duration(time.Now().UnixNano())
	f.putToQueue()
}
