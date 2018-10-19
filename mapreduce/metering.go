package mapreduce

import (
	"fmt"
	"reflect"
	"time"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/usage"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

func NewMeteringMapProcess(output queue.QueueWriter, input queue.MultiQueueReader, inputCount int, docsInBuffer int, windowSize int) *MeteringHandler {
	return NewMeteringHandler([]app.MeteringProcessor{usage.NewProcessor()}, output, input, inputCount, docsInBuffer, windowSize)
}

type MeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor

	meteringQueue      queue.MultiQueueReader
	meteringQueueCount int
	zmqAppQueue        queue.QueueWriter
	docsInBuffer       int
	windowSize         int
}

func NewMeteringHandler(processors []app.MeteringProcessor, output queue.QueueWriter, inputs queue.MultiQueueReader, inputCount int, docsInBuffer int, windowSize int) *MeteringHandler {
	return &MeteringHandler{
		numberOfApps:       len(processors),
		processors:         processors,
		zmqAppQueue:        output,
		meteringQueue:      inputs,
		meteringQueueCount: inputCount,
		docsInBuffer:       docsInBuffer,
		windowSize:         windowSize,
	}
}

type subMeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor
	stashes      []*Stash

	meteringQueue queue.MultiQueueReader
	zmqAppQueue   queue.QueueWriter

	queueIndex int

	lastFlush    time.Duration
	counterLatch int
	statItems    []stats.StatItem

	statsdCounter []StatsdCounter
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
		processors:   dupProcessors,
		stashes:      make([]*Stash, h.numberOfApps),

		meteringQueue: h.meteringQueue,
		zmqAppQueue:   h.zmqAppQueue,

		queueIndex: index,

		lastFlush: time.Duration(time.Now().UnixNano()),

		statItems: make([]stats.StatItem, h.numberOfApps*3),

		statsdCounter: make([]StatsdCounter, h.numberOfApps*2),
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(h.docsInBuffer, h.windowSize)
		handler.statItems[i].Name = h.processors[i].GetName()
		handler.statItems[i].StatType = stats.COUNT_TYPE
		handler.statItems[i+handler.numberOfApps].Name = fmt.Sprintf("%s_doc_counter", h.processors[i].GetName())
		handler.statItems[i+handler.numberOfApps].StatType = stats.COUNT_TYPE
		handler.statItems[i+handler.numberOfApps*2].Name = fmt.Sprintf("%s_max_doc_counter", h.processors[i].GetName())
		handler.statItems[i+handler.numberOfApps*2].StatType = stats.COUNT_TYPE
	}
	return &handler
}

func (f *subMeteringHandler) GetCounter() interface{} {
	oldLatch := f.counterLatch
	if f.counterLatch == 0 {
		f.counterLatch = f.numberOfApps
	} else {
		f.counterLatch = 0
	}
	for i := 0; i < f.numberOfApps; i++ {
		if f.statsdCounter[i+oldLatch].flowCounter != 0 {
			f.statItems[i+f.numberOfApps].Value = f.statsdCounter[i+oldLatch].docCounter / f.statsdCounter[i+oldLatch].flowCounter
		}
		f.statItems[i+f.numberOfApps*2].Value = f.statsdCounter[i+oldLatch].maxCounter
		f.statsdCounter[i+oldLatch].docCounter = 0
		f.statsdCounter[i+oldLatch].flowCounter = 0
		f.statsdCounter[i+oldLatch].maxCounter = 0
	}

	return f.statItems
}

func (f *subMeteringHandler) putToQueue() {
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

func (f *MeteringHandler) Start() {
	for i := 0; i < f.meteringQueueCount; i++ {
		go f.newSubMeteringHandler(i).Process()
	}
}

func (f *subMeteringHandler) Process() error {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := f.meteringQueue.Gets(queue.HashKey(f.queueIndex), elements)
		for _, e := range elements[:n] {
			if e == nil { // tick
				f.Flush()
				continue
			}

			metering := e.(*datatype.MetaPacket)
			if metering.PolicyData == nil || metering.EndpointData == nil { // shouldn't happen
				log.Warningf("drop invalid packet with nil PolicyData or EndpointData %v", metering)
				datatype.ReleaseMetaPacket(metering)
				continue
			}
			now := time.Duration(time.Now().UnixNano())
			if metering.Timestamp > now+time.Minute {
				log.Infof("drop invalid packet with a future timestamp (+%s)", metering.Timestamp-now)
				datatype.ReleaseMetaPacket(metering)
				// FIXME: add statsd counter, remove log
				continue
			}

			for i, processor := range f.processors {
				docs := processor.Process(metering, false)
				f.statsdCounter[i+f.counterLatch].docCounter += uint64(len(docs))
				f.statsdCounter[i+f.counterLatch].flowCounter++
				if uint64(len(docs)) > f.statsdCounter[i+f.counterLatch].maxCounter {
					f.statsdCounter[i+f.counterLatch].maxCounter = uint64(len(docs))
				}
				for {
					docs = f.stashes[i].Add(docs)
					if docs == nil {
						break
					}
					f.Flush()
				}
			}
			datatype.ReleaseMetaPacket(metering)
		}
		if time.Duration(time.Now().UnixNano())-f.lastFlush >= FLUSH_INTERVAL {
			f.Flush()
		}
	}
}

func (f *subMeteringHandler) Flush() {
	f.lastFlush = time.Duration(time.Now().UnixNano())
	f.putToQueue()
}
