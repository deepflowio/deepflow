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

package prometheus_exporter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	logging "github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
	"golang.org/x/net/context"

	ingester_common "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	exporters_cfg "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("prometheus_exporter")

const (
	QUEUE_BATCH_COUNT = 1024
)

type PrometheusExporter struct {
	ctx    context.Context
	cancel context.CancelFunc

	index                 int
	Addr                  string
	dataQueues            queue.FixedMultiQueue
	queueCount            int
	requestFailedCounters []int

	universalTagsManager *utag.UniversalTagsManager
	config               *exporters_cfg.ExporterCfg
	counter              *Counter
	lastCounter          Counter
	running              bool

	utils.Closable
}

type Counter struct {
	RecvCounter      int64 `statsd:"recv-count"`
	SendCounter      int64 `statsd:"send-count"`
	SendBatchCounter int64 `statsd:"send-batch-count"`
	DropCounter      int64 `statsd:"drop-count"`
	DropBatchCounter int64 `statsd:"drop-batch-count"`
	ExportUsedTimeNs int64 `statsd:"export-used-time-ns"`
}

func (e *PrometheusExporter) GetCounter() interface{} {
	var counter Counter
	counter, *e.counter = *e.counter, Counter{}
	e.lastCounter = counter
	return &counter
}

func NewPrometheusExporter(index int, config *exporters_cfg.ExporterCfg, universalTagsManager *utag.UniversalTagsManager) *PrometheusExporter {
	ctx, cancel := context.WithCancel(context.Background())
	dataQueues := queue.NewOverwriteQueues(
		fmt.Sprintf("prometheus_exporter_%d", index), queue.HashKey(config.QueueCount), config.QueueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(common.ExportItem).Release() }),
		ingester_common.QUEUE_STATS_MODULE_INGESTER)

	exporter := &PrometheusExporter{
		index:                 index,
		dataQueues:            dataQueues,
		queueCount:            config.QueueCount,
		requestFailedCounters: make([]int, config.QueueCount),
		universalTagsManager:  universalTagsManager,
		config:                config,
		counter:               &Counter{},
		ctx:                   ctx,
		cancel:                cancel,
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_PROMETHEUS_EXPORTER, exporter)
	ingester_common.RegisterCountableForIngester("exporter", exporter, stats.OptionStatTags{
		"type": "promethues", "index": strconv.Itoa(index)})
	log.Infof("promethues exporter %d created", index)
	return exporter
}

func (e *PrometheusExporter) Put(items ...interface{}) {
	e.counter.RecvCounter++
	e.dataQueues.Put(queue.HashKey(int(e.counter.RecvCounter)%e.queueCount), items...)
}

func (e *PrometheusExporter) Start() {
	if e.running {
		log.Warningf("promethues exporter %d already running", e.index)
		return
	}
	e.running = true
	for i := 0; i < e.queueCount; i++ {
		go e.queueProcess(int(i))
	}
	log.Infof("promethues exporter %d started %d queue", e.index, e.queueCount)
}

func (e *PrometheusExporter) Close() {
	e.running = false
	e.Close()
	e.cancel()
	log.Infof("promethues exporter %d stopping", e.index)
}

func (e *PrometheusExporter) queueProcess(queueID int) {
	items := make([]interface{}, QUEUE_BATCH_COUNT)
	batchs := make([]prompb.TimeSeries, 0, e.config.BatchSize)

	doReq := func() {
		batchCount := len(batchs)
		if batchCount == 0 {
			return
		}
		now := time.Now()
		if err := e.sendRequest(queueID, batchs); err != nil {
			if e.counter.DropCounter == 0 {
				log.Warningf("failed to send promrw request,requestFaildCounter=%d, err: %v", e.requestFailedCounters[queueID], err)
			}
			e.counter.DropCounter += int64(batchCount)
			e.counter.DropBatchCounter++
		} else {
			e.counter.SendCounter += int64(batchCount)
			e.counter.SendBatchCounter++
		}
		e.counter.ExportUsedTimeNs += int64(time.Since(now))
		batchs = batchs[:0]
	}

	for e.running {
		n := e.dataQueues.Gets(queue.HashKey(queueID), items)
		for _, item := range items[:n] {
			if item == nil {
				doReq()
				continue
			}
			exportItem, ok := item.(common.ExportItem)
			if !ok {
				e.counter.DropCounter++
				continue
			}

			ts, err := exportItem.EncodeTo(exporters_cfg.PROTOCOL_PROMETHEUS, e.universalTagsManager, e.config)
			if err != nil {
				if e.counter.DropCounter == 0 {
					log.Warningf("failed to encode promrw request, err: %v", err)
				}
				e.counter.DropCounter++
				exportItem.Release()
				continue
			}
			timeSeries := ts.([]prompb.TimeSeries)
			batchs = append(batchs, timeSeries...)
			batchCount := len(batchs)
			if batchCount >= e.config.BatchSize {
				doReq()
			}
			exportItem.Release()
		}
	}
}

func (e *PrometheusExporter) HandleSimpleCommand(op uint16, arg string) string {
	return fmt.Sprintf("promethues exporter %d last 10s counter: %+v", e.index, e.lastCounter)
}

func (e *PrometheusExporter) getEndpont(queueID int) string {
	l := len(e.config.RandomEndpoints)
	return e.config.RandomEndpoints[e.requestFailedCounters[queueID]%l]
}

func (e *PrometheusExporter) sendRequest(queueID int, batchs []prompb.TimeSeries) error {
	wr := &prompb.WriteRequest{Timeseries: batchs}
	data, err := proto.Marshal(wr)
	if err != nil {
		return err
	}
	buf := make([]byte, len(data), cap(data))
	compressedData := snappy.Encode(buf, data)

	endpoint := e.getEndpont(queueID)
	req, err := http.NewRequestWithContext(e.ctx, "POST", endpoint, bytes.NewReader(compressedData))
	if err != nil {
		e.requestFailedCounters[queueID]++
		return err
	}

	// Add necessary headers specified by:
	// https://cortexmetrics.io/docs/apis/#remote-api
	req.Header.Add("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	// inject extra headers
	for k, v := range e.config.ExtraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.requestFailedCounters[queueID]++
		return err
	}
	defer resp.Body.Close()

	// 5xx errors are recoverable and the writer should retry?
	// Reference for different behavior according to status code:
	// https://github.com/prometheus/prometheus/pull/2552/files#diff-ae8db9d16d8057358e49d694522e7186
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		e.requestFailedCounters[queueID]++
		return fmt.Errorf("remote write returned HTTP status %v; err = %w: %s", resp.Status, err, body)
	}

	return nil
}

var prompbTimeSeriesPool = pool.NewLockFreePool(func() interface{} {
	return &prompb.TimeSeries{
		Samples: make([]prompb.Sample, 1),
	}
})

func AcquirePrompbTimeSeries() *prompb.TimeSeries {
	return prompbTimeSeriesPool.Get().(*prompb.TimeSeries)
}

func ReleasePrompbTimeSeries(t *prompb.TimeSeries) {
	if t == nil {
		return
	}
	t.Labels = t.Labels[:0]
	prompbTimeSeriesPool.Put(t)
}
