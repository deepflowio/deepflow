package mapreduce

import (
	"errors"
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

func isValidMetering(metering datatype.MetaPacket) bool {
	meteringTime := metering.Timestamp
	curTime := time.Duration(time.Now().UnixNano())
	if meteringTime == 0 || meteringTime > curTime {
		return false
	}
	return true
}

func (f *MeteringHandler) timeout() {
	timer := time.NewTimer(time.Minute)
	for {
		<-timer.C
		timer.Reset(time.Minute)
		flushMetering := datatype.MetaPacket{Timestamp: 0}
		for i := 0; i < f.meteringQueueCount; i++ {
			f.meteringQueue.Put(queue.HashKey(i), &flushMetering)
		}
	}
}

func (f *MeteringHandler) Start() {
	go f.timeout()
	for i := 0; i < f.meteringQueueCount; i++ {
		go newSubHandler(f.processors, f.zmqAppQueue, f.meteringQueue, i).Process()
	}
}

func (f *subHandler) Process() error {
	for {
		metering := f.meteringQueue.Get(queue.HashKey(f.queueIndex)).(*datatype.MetaPacket)
		if metering.Timestamp == 0 && f.NeedFlush() {
			f.Flush()
		}

		if !isValidMetering(*metering) {
			return errors.New("flow timestamp incorrect and droped")
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

func (f *subHandler) Flush() {
	f.putToQueue()
	f.lastProcess = time.Duration(time.Now().UnixNano())
}

func (f *subHandler) NeedFlush() bool {
	return time.Duration(time.Now().UnixNano())-f.lastProcess > time.Minute
}
