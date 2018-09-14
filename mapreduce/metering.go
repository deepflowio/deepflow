package mapreduce

import (
	"errors"

	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/usage"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

func NewMeteringMapProcess(zmqMeteringQueue queue.QueueWriter) *MeteringHandler {
	return NewMeteringHandler([]app.MeteringProcessor{usage.NewProcessor()}, zmqMeteringQueue)
}

type meteringAppStats struct {
	UsageEmitCounter uint64 `statsd:"usage_doc"`
	//TO DO: add other apps
}

type MeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor
	stashes      []*Stash

	lastProcess time.Duration

	zmqAppQueue queue.QueueWriter
	emitCounter []uint64
}

func NewMeteringHandler(processors []app.MeteringProcessor, zmqAppQueue queue.QueueWriter) *MeteringHandler {
	nApps := len(processors)
	handler := MeteringHandler{
		numberOfApps: len(processors),
		processors:   processors,
		lastProcess:  time.Duration(time.Now().UnixNano()),
		stashes:      make([]*Stash, nApps),
		zmqAppQueue:  zmqAppQueue,
		emitCounter:  make([]uint64, nApps),
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(DOCS_IN_BUFFER)
	}
	stats.RegisterCountable("metering_mapper", &handler)
	return &handler
}

func (f *MeteringHandler) GetCounter() interface{} {
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

func (f *MeteringHandler) putToQueue() {
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

func (f *MeteringHandler) Process(metering datatype.MetaPacket) error {

	if !isValidMetering(metering) {
		return errors.New("flow timestamp incorrect and droped")
	}

	flush := false

	for i, processor := range f.processors {
		f.stashes[i].Add(processor.Process(metering, false)...)
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

func (f *MeteringHandler) Flush() {
	f.putToQueue()
	f.lastProcess = time.Duration(time.Now().UnixNano())
}

func (f *MeteringHandler) NeedFlush() bool {
	return time.Duration(time.Now().UnixNano())-f.lastProcess > time.Minute
}
