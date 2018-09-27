package mapreduce

import (
	"reflect"
	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/usage"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func NewMeteringMapProcess(input queue.QueueWriter, output queue.MultiQueue, outputCount int) *MeteringHandler {
	return NewMeteringHandler([]app.MeteringProcessor{usage.NewProcessor()}, input, output, outputCount)
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

	queueIndex int
}

func newSubHandler(processors []app.MeteringProcessor, output queue.QueueWriter, inputs queue.MultiQueue, index int) *subHandler {
	nApps := len(processors)
	dupProcessors := make([]app.MeteringProcessor, nApps)
	for i := range processors {
		dupProcessors[i] = reflect.New(reflect.ValueOf(processors[i]).Elem().Type()).Interface().(app.MeteringProcessor)
		dupProcessors[i].Prepare()
	}
	handler := subHandler{
		numberOfApps:  len(processors),
		processors:    dupProcessors,
		lastProcess:   time.Duration(time.Now().UnixNano()),
		stashes:       make([]*Stash, nApps),
		zmqAppQueue:   output,
		meteringQueue: inputs,
		queueIndex:    index,
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(DOCS_IN_BUFFER, WINDOW_SIZE)
	}
	return &handler
}

func (f *subHandler) putToQueue() {
	for _, stash := range f.stashes {
		docs := stash.Dump()
		for i := 0; i < len(docs); i += QUEUE_BATCH_SIZE {
			if i+QUEUE_BATCH_SIZE <= len(docs) {
				f.zmqAppQueue.Put(docs[i : i+QUEUE_BATCH_SIZE]...)
			} else {
				f.zmqAppQueue.Put(docs[i:]...)
			}
		}
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
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

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

			for i, processor := range f.processors {
				docs := processor.Process(metering, false)
				for {
					docs = f.stashes[i].Add(docs)
					if docs == nil {
						break
					}
					f.Flush()
				}
			}
		}
		f.lastProcess = time.Duration(time.Now().UnixNano())
	}
}

func (f *subHandler) Flush() {
	f.putToQueue()
	f.lastProcess = time.Duration(time.Now().UnixNano())
}

func (f *subHandler) NeedFlush() bool {
	return time.Duration(time.Now().UnixNano())-f.lastProcess > time.Minute
}
