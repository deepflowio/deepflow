package mapreduce

import (
	"errors"

	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/consolelog"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/flow"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/geo"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/perf"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

const (
	perfSlots = 2
)

const GEO_FILE_LOCATION = "/usr/share/droplet/ip_info_mini.json"

func NewFlowMapProcess(zmqAppQueue queue.QueueWriter) *FlowHandler {
	return NewFlowHandler([]app.FlowProcessor{
		flow.NewProcessor(),
		perf.NewProcessor(),
		geo.NewProcessor(GEO_FILE_LOCATION),
		consolelog.NewProcessor(),
	}, zmqAppQueue)
}

type flowAppStats struct {
	EpcEmitCounter uint64 `statsd:"epc_doc"`
	//TO DO: add other apps

}

type FlowHandler struct {
	numberOfApps int
	processors   []app.FlowProcessor
	stashes      []*Stash

	lastProcess time.Duration

	zmqAppQueue queue.QueueWriter
	emitCounter []uint64
}

func NewFlowHandler(processors []app.FlowProcessor, zmqAppQueue queue.QueueWriter) *FlowHandler {
	nApps := len(processors)
	handler := FlowHandler{
		numberOfApps: nApps,
		processors:   processors,
		stashes:      make([]*Stash, nApps),
		lastProcess:  time.Duration(time.Now().UnixNano()),
		zmqAppQueue:  zmqAppQueue,
		emitCounter:  make([]uint64, nApps),
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(DOCS_IN_BUFFER)
	}
	stats.RegisterCountable("flow_mapper", &handler)
	return &handler
}

func (f *FlowHandler) GetCounter() interface{} {
	counter := &flowAppStats{}
	for i := 0; i < f.numberOfApps; i++ {
		switch f.processors[i].GetName() {
		case "EpcFlowTopo":
			counter.EpcEmitCounter = f.emitCounter[i]
			f.emitCounter[i] = 0
			//TO DO: add other apps
		}
	}
	return counter
}

func (f *FlowHandler) putToQueue() {
	for i, stash := range f.stashes {
		docs := stash.Dump()
		for _, doc := range docs {
			f.zmqAppQueue.Put(doc)
		}
		f.emitCounter[i] += uint64(len(docs))
		stash.Clear()
	}
}

func isValidFlow(flow datatype.TaggedFlow) bool {
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

func (f *FlowHandler) Process(flow datatype.TaggedFlow) error {
	flush := false

	if !isValidFlow(flow) {
		return errors.New("flow timestamp incorrect and droped")
	}

	for i, processor := range f.processors {
		f.stashes[i].Add(processor.Process(flow, false)...)
		if f.stashes[i].Full() {
			flush = true
		}
	}

	if flush {
		f.Flush()
	}

	f.lastProcess = time.Duration(time.Now().UnixNano())
	return nil
}

func (f *FlowHandler) Flush() {
	f.putToQueue()
	f.lastProcess = time.Duration(time.Now().UnixNano())
}

func (f *FlowHandler) NeedFlush() bool {
	return time.Duration(time.Now().UnixNano())-f.lastProcess > time.Minute
}
