package mapreduce

import (
	"fmt"

	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/usage"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

func NewMeteringMapProcess(input queue.QueueWriter, output queue.MultiQueue, outputCount int) *MeteringHandler {
	return NewMeteringHandler([]app.MeteringProcessor{usage.NewProcessor()}, input, output, outputCount)
}

type meteringAppStats struct {
	UsageEmitCounter uint64 `statsd:"usage_doc"`
	//TO DO: add other apps
}

type MeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor

	meteringQueue      queue.MultiQueue
	meteringQueueCount int
	zmqAppQueue        queue.QueueWriter
}

func NewMeteringHandler(processors []app.MeteringProcessor, output queue.QueueWriter, inputs queue.MultiQueue, inputCount int) *MeteringHandler {
	handler := MeteringHandler{
		numberOfApps:       len(processors),
		processors:         processors,
		zmqAppQueue:        output,
		meteringQueue:      inputs,
		meteringQueueCount: inputCount,
	}
	return &handler
}

type subHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor
	stashes      []*Stash

	lastProcess        time.Duration
	meteringQueue      queue.MultiQueue
	meteringQueueCount int
	zmqAppQueue        queue.QueueWriter
	emitCounter        []uint64

	queueIndex int
}

func newSubHandler(processors []app.MeteringProcessor, output queue.QueueWriter, inputs queue.MultiQueue, index int) *subHandler {
	nApps := len(processors)
	handler := subHandler{
		numberOfApps:  len(processors),
		processors:    processors,
		lastProcess:   time.Duration(time.Now().UnixNano()),
		stashes:       make([]*Stash, nApps),
		zmqAppQueue:   output,
		emitCounter:   make([]uint64, nApps),
		meteringQueue: inputs,
		queueIndex:    index,
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(DOCS_IN_BUFFER)
	}
	stats.RegisterCountable(fmt.Sprintf("metering_mapper_%d", index), &handler)
	return &handler
}

func (f *subHandler) GetCounter() interface{} {
	counter := &meteringAppStats{}
	for i := 0; i < f.numberOfApps; i++ {
		switch f.processors[i].GetName() {
		case "BwusageIspUsageInfo":
			counter.UsageEmitCounter = f.emitCounter[i]
			f.emitCounter[i] = 0
			//TO DO: add other apps
		}
	}
	return counter
}

func (f *subHandler) putToQueue() {
	for i, stash := range f.stashes {
		docs := stash.Dump()
		for _, doc := range docs {
			f.zmqAppQueue.Put(doc)
		}
		f.emitCounter[i] += uint64(len(docs))
		stash.Clear()
	}
}

func (f *MeteringHandler) startTicker() {
	for range time.NewTicker(time.Minute).C {
		for i := 0; i < f.meteringQueueCount; i++ {
			f.meteringQueue.Put(queue.HashKey(i), nil)
		}
	}
}

func (f *MeteringHandler) Start() {
	go f.startTicker()
	for i := 0; i < f.meteringQueueCount; i++ {
		go newSubHandler(f.processors, f.zmqAppQueue, f.meteringQueue, i).Process()
	}
}

func (f *subHandler) Process() error {
	batchSize := 4096
	elements := make([]interface{}, batchSize)

	for {
		n := f.meteringQueue.Gets(queue.HashKey(f.queueIndex), elements)
		for _, e := range elements[:n] {
			if e == nil { // tick
				if f.NeedFlush() {
					f.Flush()
				}
				continue
			}

			metering := e.(*datatype.MetaPacket)
			if metering.PolicyData == nil || metering.EndpointData == nil { // shouldn't happen
				log.Warningf("drop invalid packet with nil PolicyData or EndpointData %v", metering)
				continue
			}
			now := time.Duration(time.Now().UnixNano())
			if metering.Timestamp > now+time.Minute {
				log.Infof("drop invalid packet with a future timestamp (+%s)", metering.Timestamp-now)
				// FIXME: add statsd counter, remove log
				continue
			}

			flush := false
			for i, processor := range f.processors {
				f.stashes[i].Add(processor.Process(*metering, false)...)
				if f.stashes[i].Full() {
					flush = true
				}
			}
			if flush {
				f.Flush()
			}
		}
	}
}

func (f *subHandler) Flush() {
	f.putToQueue()
	f.lastProcess = time.Duration(time.Now().UnixNano())
}

func (f *subHandler) NeedFlush() bool {
	return time.Duration(time.Now().UnixNano())-f.lastProcess > time.Minute
}
