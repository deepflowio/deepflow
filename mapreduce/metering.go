package mapreduce

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"math/rand"

	"gitlab.x.lan/application/droplet-app/pkg/mapper/usage"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

func NewMeteringMapProcess(
	output queue.MultiQueueWriter, input queue.MultiQueueReader,
	inputCount, docsInBuffer, variedDocLimit, windowSize, windowMoveMargin int,
) *MeteringHandler {
	return NewMeteringHandler(
		[]app.MeteringProcessor{usage.NewProcessor()}, output, input,
		inputCount, docsInBuffer, variedDocLimit, windowSize, windowMoveMargin)
}

type MeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor

	meteringQueue      queue.MultiQueueReader
	meteringQueueCount int
	zmqAppQueue        queue.MultiQueueWriter
	docsInBuffer       int
	variedDocLimit     int
	windowSize         int
	windowMoveMargin   int
}

func NewMeteringHandler(
	processors []app.MeteringProcessor,
	output queue.MultiQueueWriter, inputs queue.MultiQueueReader,
	inputCount, docsInBuffer, variedDocLimit, windowSize, windowMoveMargin int,
) *MeteringHandler {
	return &MeteringHandler{
		numberOfApps:       len(processors),
		processors:         processors,
		zmqAppQueue:        output,
		meteringQueue:      inputs,
		meteringQueueCount: inputCount,
		docsInBuffer:       docsInBuffer,
		variedDocLimit:     variedDocLimit,
		windowSize:         windowSize,
		windowMoveMargin:   windowMoveMargin,
	}
}

type subMeteringHandler struct {
	numberOfApps int
	processors   []app.MeteringProcessor
	stashes      []*Stash

	meteringQueue queue.MultiQueueReader
	zmqAppQueue   queue.MultiQueueWriter

	queueIndex int
	hashKey    queue.HashKey

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
		hashKey:    queue.HashKey(rand.Int()),

		lastFlush: time.Duration(time.Now().UnixNano()),

		statItems: make([]stats.StatItem, h.numberOfApps*5),

		statsdCounter: make([]StatsdCounter, h.numberOfApps*2),
	}
	for i := 0; i < handler.numberOfApps; i++ {
		handler.stashes[i] = NewStash(h.docsInBuffer, h.variedDocLimit, h.windowSize, h.windowMoveMargin)
		handler.statItems[i].Name = h.processors[i].GetName()
		handler.statItems[i+handler.numberOfApps].Name = fmt.Sprintf("%s_avg_doc_counter", h.processors[i].GetName())
		handler.statItems[i+handler.numberOfApps*2].Name = fmt.Sprintf("%s_max_doc_counter", h.processors[i].GetName())
		handler.statItems[i+handler.numberOfApps*3].Name = fmt.Sprintf("%s_rejected_doc", h.processors[i].GetName())
		handler.statItems[i+handler.numberOfApps*4].Name = fmt.Sprintf("%s_flush", h.processors[i].GetName())
	}
	stats.RegisterCountable("metering_mapper", &handler, stats.OptionStatTags{"index": strconv.Itoa(index)})
	return &handler
}

func (h *subMeteringHandler) GetCounter() interface{} {
	oldLatch := h.counterLatch
	if h.counterLatch == 0 {
		h.counterLatch = h.numberOfApps
	} else {
		h.counterLatch = 0
	}
	for i := 0; i < h.numberOfApps; i++ {
		h.statItems[i].Value = h.statsdCounter[i+oldLatch].emitCounter
		if h.statsdCounter[i+oldLatch].flowCounter != 0 {
			h.statItems[i+h.numberOfApps].Value =
				h.statsdCounter[i+oldLatch].docCounter / h.statsdCounter[i+oldLatch].flowCounter
		} else {
			h.statItems[i+h.numberOfApps].Value = 0
		}
		h.statItems[i+h.numberOfApps*2].Value = h.statsdCounter[i+oldLatch].maxCounter
		h.statItems[i+h.numberOfApps*3].Value = h.statsdCounter[i+oldLatch].rejectionCounter
		h.statItems[i+h.numberOfApps*4].Value = h.statsdCounter[i+oldLatch].flushCounter
		h.statsdCounter[i+oldLatch].emitCounter = 0
		h.statsdCounter[i+oldLatch].docCounter = 0
		h.statsdCounter[i+oldLatch].flowCounter = 0
		h.statsdCounter[i+oldLatch].maxCounter = 0
		h.statsdCounter[i+oldLatch].rejectionCounter = 0
		h.statsdCounter[i+oldLatch].flushCounter = 0
	}

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
				h.zmqAppQueue.Put(h.hashKey, docs[j:j+QUEUE_BATCH_SIZE]...)
			} else {
				h.zmqAppQueue.Put(h.hashKey, docs[j:]...)
			}
			h.hashKey++
		}
		h.statsdCounter[i+h.counterLatch].emitCounter += uint64(len(docs))
		stash.Clear()
	}
}

func (h *MeteringHandler) Start() {
	for i := 0; i < h.meteringQueueCount; i++ {
		go h.newSubMeteringHandler(i).Process()
	}
}

func (h *subMeteringHandler) Process() error {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := h.meteringQueue.Gets(queue.HashKey(h.queueIndex), elements)
		for _, e := range elements[:n] {
			if e == nil { // tick
				h.Flush(-1)
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

			for i, processor := range h.processors {
				docs := processor.Process(metering, false)
				rejected := uint64(0)
				h.statsdCounter[i+h.counterLatch].docCounter += uint64(len(docs))
				h.statsdCounter[i+h.counterLatch].flowCounter++
				if uint64(len(docs)) > h.statsdCounter[i+h.counterLatch].maxCounter {
					h.statsdCounter[i+h.counterLatch].maxCounter = uint64(len(docs))
				}
				for {
					docs, rejected = h.stashes[i].Add(docs)
					h.statsdCounter[i+h.counterLatch].rejectionCounter += rejected
					if docs == nil {
						break
					}
					h.statsdCounter[i+h.counterLatch].flushCounter++
					h.Flush(i)
				}
			}
			datatype.ReleaseMetaPacket(metering)
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
