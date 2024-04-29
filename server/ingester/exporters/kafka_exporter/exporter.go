/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kafka_exporter

import (
	"fmt"
	"strconv"
	"time"

	"github.com/IBM/sarama"
	logging "github.com/op/go-logging"

	ingester_common "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	exporters_cfg "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("kafka_exporter")

const (
	QUEUE_BATCH_COUNT = 1024
)

type KafkaExporter struct {
	index                int
	Addr                 string
	dataQueues           queue.FixedMultiQueue
	queueCount           int
	producers            []sarama.SyncProducer
	universalTagsManager *utag.UniversalTagsManager
	config               *exporters_cfg.ExporterCfg
	counter              *Counter
	lastCounter          Counter
	running              bool

	utils.Closable
}

type Counter struct {
	RecvCounter          int64 `statsd:"recv-count"`
	SendCounter          int64 `statsd:"send-count"`
	SendBatchCounter     int64 `statsd:"send-batch-count"`
	ExportUsedTimeNs     int64 `statsd:"export-used-time-ns"`
	DropCounter          int64 `statsd:"drop-count"`
	DropBatchCounter     int64 `statsd:"drop-batch-count"`
	DropNoTraceIDCounter int64 `statsd:"drop-no-traceid-count"`
}

func (e *KafkaExporter) GetCounter() interface{} {
	var counter Counter
	counter, *e.counter = *e.counter, Counter{}
	e.lastCounter = counter
	return &counter
}

func NewKafkaExporter(index int, config *exporters_cfg.ExporterCfg, universalTagsManager *utag.UniversalTagsManager) *KafkaExporter {
	dataQueues := queue.NewOverwriteQueues(
		fmt.Sprintf("kafka_exporter_%d", index), queue.HashKey(config.QueueCount), config.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(common.ExportItem).Release() }),
		ingester_common.QUEUE_STATS_MODULE_INGESTER)

	exporter := &KafkaExporter{
		index:                index,
		dataQueues:           dataQueues,
		queueCount:           config.QueueCount,
		universalTagsManager: universalTagsManager,
		producers:            make([]sarama.SyncProducer, config.QueueCount),
		config:               config,
		counter:              &Counter{},
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_KAFKA_EXPORTER, exporter)
	ingester_common.RegisterCountableForIngester("exporter", exporter, stats.OptionStatTags{
		"type": "kafka", "index": strconv.Itoa(index)})
	log.Infof("kafka exporter %d created", index)
	return exporter
}

func (e *KafkaExporter) Put(items ...interface{}) {
	e.counter.RecvCounter++
	e.dataQueues.Put(queue.HashKey(int(e.counter.RecvCounter)%e.queueCount), items...)
}

func (e *KafkaExporter) Start() {
	if e.running {
		log.Warningf("kafka exporter %d already running", e.index)
		return
	}
	e.running = true
	for i := 0; i < e.queueCount; i++ {
		go e.queueProcess(int(i))
	}
	log.Infof("kafka exporter %d started %d queue", e.index, e.queueCount)
}

func (e *KafkaExporter) Close() {
	e.Closable.Close()
	e.running = false
	for i := 0; i < e.queueCount; i++ {
		if e.producers[i] != nil {
			e.producers[i].Close()
			e.producers[i] = nil
		}
	}
	log.Infof("kafka exporter %d stopping", e.index)
}

func (e *KafkaExporter) newProducer(id int) error {
	// create producer config
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 3
	config.Producer.Return.Successes = true
	config.Producer.Compression = sarama.CompressionSnappy

	config.Net.SASL.Enable = e.config.Sasl.Enabled
	config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	config.Net.SASL.User = e.config.Sasl.Username
	config.Net.SASL.Password = e.config.Sasl.Password

	producer, err := sarama.NewSyncProducer(e.config.Endpoints, config)
	if err != nil {
		return err
	}

	e.producers[id] = producer
	return nil
}

func (e *KafkaExporter) queueProcess(queueID int) {
	items := make([]interface{}, QUEUE_BATCH_COUNT)
	batch := []*sarama.ProducerMessage{}

	for e.running {
		n := e.dataQueues.Gets(queue.HashKey(queueID), items)
		for _, item := range items[:n] {
			if item == nil {
				e.exportBatch(queueID, batch)
				batch = batch[:0]
				continue
			}
			exportItem, ok := item.(common.ExportItem)
			if !ok {
				e.counter.DropCounter++
				continue
			}

			json, err := exportItem.EncodeTo(exporters_cfg.PROTOCOL_KAFKA, e.universalTagsManager, e.config)
			if err != nil {
				if e.counter.DropCounter == 0 {
					log.Warningf("kafka encode failed, err: %s", err)
				}
				e.counter.DropCounter++
				exportItem.Release()
				continue
			}

			jsonStr := json.(string)
			topic := e.config.Topic
			if topic == "" {
				topic = exporters_cfg.DataSourceID(exportItem.DataSource()).TopicString()
			}
			batch = append(batch,
				&sarama.ProducerMessage{
					Topic:     topic,
					Key:       nil,
					Value:     sarama.ByteEncoder(utils.Slice(jsonStr)),
					Timestamp: time.UnixMicro(exportItem.TimestampUs()),
				},
			)
			if len(batch) >= e.config.BatchSize {
				log.Debugf("kafka: %s \n %+v", jsonStr, item)
				e.exportBatch(queueID, batch)
				batch = batch[:0]
			}
			exportItem.Release()
		}
	}
}

func (e *KafkaExporter) exportBatch(queueID int, batch []*sarama.ProducerMessage) {
	defer func() {
		if r := recover(); r != nil {
			log.Warningf("kafka export error: %s", r)
		}
	}()

	if len(batch) == 0 {
		return
	}

	if utils.IsNil(e.producers[queueID]) {
		err := e.newProducer(queueID)
		if err != nil {
			if e.counter.DropCounter == 0 {
				log.Warningf("exporter %d queue %d new kafka producer failed. err: %s", e.index, queueID, err)
			}
			e.counter.DropCounter += int64(len(batch))
			e.counter.DropBatchCounter++
			return
		}
	}

	producer := e.producers[queueID]

	now := time.Now()
	if err := producer.SendMessages(batch); err != nil {
		if e.counter.DropCounter == 0 {
			log.Warningf("exporter %d send kafka messages failed. err: %s", e.index, err)
		}
		e.counter.DropCounter += int64(len(batch))
		e.counter.DropBatchCounter++
	} else {
		e.counter.SendCounter += int64(len(batch))
		e.counter.SendBatchCounter++
	}

	e.counter.ExportUsedTimeNs += int64(time.Since(now))
}

func (e *KafkaExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("kafka exporter %d last 10s counter: %+v", e.index, e.lastCounter)
}
