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
	"google.golang.org/grpc"

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
	grpcConns            []*grpc.ClientConn
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
	kafkaConfig := config

	dataQueues := queue.NewOverwriteQueues(
		fmt.Sprintf("kafka_exporter_%d", index), queue.HashKey(kafkaConfig.QueueCount), kafkaConfig.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(common.ExportItem).Release() }),
		ingester_common.QUEUE_STATS_MODULE_INGESTER)

	exporter := &KafkaExporter{
		index:                index,
		dataQueues:           dataQueues,
		queueCount:           kafkaConfig.QueueCount,
		universalTagsManager: universalTagsManager,
		grpcConns:            make([]*grpc.ClientConn, kafkaConfig.QueueCount),
		config:               kafkaConfig,
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
	log.Infof("kafka exporter %d stopping", e.index)
}

func (e *KafkaExporter) queueProcess(queueID int) {
	var batchCount int
	items := make([]interface{}, QUEUE_BATCH_COUNT)

	// 创建 Kafka 生产者配置
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 3
	config.Producer.Return.Successes = true
	config.Producer.Compression = sarama.CompressionSnappy // 设置压缩算法为 Snappy

	producer, err := sarama.NewSyncProducer([]string{"localhost:9092"}, config)
	if err != nil {
		log.Fatalf("Error creating Kafka producer: %v", err)
	}
	defer producer.Close()

	batch := []*sarama.ProducerMessage{}

	for e.running {
		n := e.dataQueues.Gets(queue.HashKey(queueID), items)
		for _, item := range items[:n] {
			if item == nil {
				if batchCount > 0 {
					if err := e.exportBatch(batch, producer); err == nil {
						e.counter.SendCounter += int64(batchCount)
					}
					batchCount = 0
				}
				continue
			}
			exportItem, ok := item.(common.ExportItem)
			if !ok {
				continue
			}
			var json string
			err := exportItem.EncodeTo(exporters_cfg.PROTOCOL_OTLP, e.universalTagsManager, e.config, json)
			if err != nil {
				continue
			}
			batch = append(batch,
				&sarama.ProducerMessage{
					Topic:     "test-topic",
					Key:       nil,
					Value:     sarama.ByteEncoder(json), // 设置消息值为压缩前的 JSON 数据
					Timestamp: time.Now(),
				},
			)
			batchCount++
			if batchCount >= e.config.BatchSize {
				if err := e.exportBatch(batch, producer); err == nil {
					e.counter.SendCounter += int64(batchCount)
				}
				batchCount = 0
			}
			exportItem.Release()
		}
	}
}

func (e *KafkaExporter) exportBatch(batch []*sarama.ProducerMessage, producer sarama.SyncProducer) error {
	defer func() {
		if r := recover(); r != nil {
			log.Warningf("kafka grpc export error: %s", r)
		}
	}()

	now := time.Now()

	// 使用 Kafka 生产者发送消息批次
	if err := producer.SendMessages(batch); err != nil {
		log.Fatalf("Error sending message batch: %v", err)
		if e.counter.DropCounter == 0 {
			log.Warningf("exporter %d send grpc traces failed. err: %s", e.index, err)
		}
		e.counter.DropCounter++
	}

	e.counter.ExportUsedTimeNs += int64(time.Since(now))
	return nil
}

func (e *KafkaExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("kafka exporter %d last 10s counter: %+v", e.index, e.lastCounter)
}
