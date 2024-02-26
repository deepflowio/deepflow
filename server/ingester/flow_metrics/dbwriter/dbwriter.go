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

package dbwriter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	flowmetricsconfig "github.com/deepflowio/deepflow/server/ingester/flow_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

var log = logging.MustGetLogger("flow_metrics.dbwriter")

const (
	CACHE_SIZE       = 10240
	QUEUE_BATCH_SIZE = 1024

	metricsFilterApp = "app"
)

// DbWriter 指标数据写入的接口定义
type DbWriter interface {
	Put(items ...interface{}) error
	Close()
}

type CkDbWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func NewCkDbWriter(addrs []string, user, password, clusterName, storagePolicy, timeZone string, ckWriterCfg config.CKWriterConfig, flowMetricsTtl flowmetricsconfig.FlowMetricsTTL, coldStorages map[string]*ckdb.ColdStorage) (DbWriter, error) {
	ckwriters := []*ckwriter.CKWriter{}
	tables := flow_metrics.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, clusterName, storagePolicy, flowMetricsTtl.VtapFlow1M, flowMetricsTtl.VtapFlow1S, flowMetricsTtl.VtapApp1M, flowMetricsTtl.VtapApp1S, coldStorages)
	for _, table := range tables {
		counterName := "metrics_1m"
		if table.ID >= uint8(flow_metrics.NETWORK_1S) && table.ID <= uint8(flow_metrics.NETWORK_MAP_1S) {
			counterName = "metrics_1s"
		} else if table.ID >= uint8(flow_metrics.APPLICATION_1S) && table.ID <= uint8(flow_metrics.APPLICATION_MAP_1S) {
			counterName = "app_1s"
		} else if table.ID >= uint8(flow_metrics.APPLICATION_1M) && table.ID <= uint8(flow_metrics.APPLICATION_MAP_1M) {
			counterName = "app_1m"
		}
		ckwriter, err := ckwriter.NewCKWriter(addrs, user, password, counterName, timeZone, table,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriter.Run()
		ckwriters = append(ckwriters, ckwriter)
	}

	return &CkDbWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *CkDbWriter) Put(items ...interface{}) error {
	caches := [flow_metrics.METRICS_TABLE_ID_MAX][]interface{}{}
	for i := range caches {
		caches[i] = make([]interface{}, 0, CACHE_SIZE)
	}
	for _, item := range items {
		doc, ok := item.(*app.Document)
		if !ok {
			log.Warningf("receive wrong type data %v", item)
			continue
		}
		id, err := doc.TableID()
		if err != nil {
			log.Warningf("doc table id not found. %v", doc)
			continue
		}
		caches[id] = append(caches[id], doc)
	}

	for i, cache := range caches {
		if len(cache) > 0 {
			w.ckwriters[i].Put(cache...)
		}
	}
	return nil
}

func (w *CkDbWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}

type PromWriterCounter struct {
	RecvMetricsCount    int64 `statsd:"recv-metrics-count"`
	RecvTimeSeriesCount int64 `statsd:"recv-timeseries-count"`

	SendFailedCount     int64 `statsd:"send-failed-count"`
	SendSucceedCount    int64 `statsd:"send-succeed-count"`
	SendTimeSeriesCount int64 `statsd:"send-timeseries-count"`
}

// PromWriter 是 prom remotewrite 的 db.Writer 实现，负责将 metrics 数据推送给到服务端
type PromWriter struct {
	ctx    context.Context
	cancel context.CancelFunc

	conf       flowmetricsconfig.PromWriterConfig
	client     *http.Client
	queues     queue.FixedMultiQueue
	queueCount int
	filter     map[string]struct{}
	seq        int32
	closed     bool
	counter    *PromWriterCounter
}

func (pw *PromWriter) GetCounter() interface{} {
	var counter *PromWriterCounter
	counter, pw.counter = pw.counter, &PromWriterCounter{}
	return counter
}

func (pw *PromWriter) Closed() bool {
	return pw.closed
}

func NewPromWriter(conf flowmetricsconfig.PromWriterConfig) *PromWriter {
	ctx, cancel := context.WithCancel(context.Background())
	filter := make(map[string]struct{})
	for _, m := range conf.MetricsFilter {
		filter[m] = struct{}{}
	}
	queues := queue.NewOverwriteQueues(
		"prometheus_remotewrite", uint8(conf.QueueCount), conf.QueueSize,
		queue.OptionFlushIndicator(time.Duration(conf.FlushTimeout)*time.Second),
		queue.OptionRelease(func(p interface{}) { ReleasePrompbTimeSeries(p.(*prompb.TimeSeries)) }),
		common.QUEUE_STATS_MODULE_INGESTER)
	pw := &PromWriter{
		ctx:        ctx,
		cancel:     cancel,
		conf:       conf,
		client:     &http.Client{Timeout: time.Second * 10},
		queues:     queues,
		queueCount: conf.QueueCount,
		filter:     filter,
		counter:    &PromWriterCounter{},
	}
	common.RegisterCountableForIngester("prom_writer", pw, stats.OptionStatTags{"queue_count": strconv.Itoa(int(conf.QueueCount))})

	for i := 0; i < conf.QueueCount; i++ {
		go pw.loopConsume(i)
	}
	return pw
}

// multi thread will call Put
func (pw *PromWriter) Put(items ...interface{}) error {
	atomic.AddInt32(&pw.seq, 1)
	var timeSeries []interface{}
	for _, item := range items {
		doc, ok := item.(*app.Document)
		if !ok {
			log.Warningf("receive wrong type data %v", item)
			continue
		}

		id, err := doc.TableID()
		if err != nil {
			log.Warningf("doc table id not found, %v", err)
			doc.Release()
			continue
		}

		// 只处理 APPLICATION_MAP_1S 这张表
		if id != uint8(flow_metrics.APPLICATION_MAP_1S) {
			doc.Release()
			continue
		}
		t := int64(doc.Timestamp) * 1000 // 转换为 ms

		var metrics map[string]float64
		// TODO: 其余 metrics 类型待实现
		if doc.Meter != nil {
			switch meter := doc.Meter.(type) {
			case *flow_metrics.AppMeter:
				if _, ok := pw.filter[metricsFilterApp]; ok {
					metrics = flow_metrics.EncodeAppMeterToMetrics(meter)
				}
			}
		}

		// 无指标则不匹配 labels
		if len(metrics) <= 0 {
			doc.Release()
			continue
		}

		var labels []prompb.Label
		if doc.Tagger != nil {
			switch tag := doc.Tagger.(type) {
			case *flow_metrics.MiniTag:
				labels = flow_metrics.EncodeMiniTagToPromLabels(tag)
			case *flow_metrics.CustomTag:
				labels = flow_metrics.EncodeCustomTagToPromLabels(tag)
			case *flow_metrics.Tag:
				labels = flow_metrics.EncodeTagToPromLabels(tag)
			}
		}

		pw.counter.RecvMetricsCount++
		for metric, value := range metrics {
			ts := AcquirePrompbTimeSeries()
			ts.Labels = append(ts.Labels, labels...)
			ts.Labels = append(ts.Labels, prompb.Label{
				Name:  "__name__",
				Value: metric,
			})
			ts.Samples[0].Value = value
			ts.Samples[0].Timestamp = t
			timeSeries = append(timeSeries, ts)
		}
		doc.Release()
	}

	if len(timeSeries) > 0 {
		pw.counter.RecvTimeSeriesCount += int64(len(timeSeries))
		pw.queues.Put(queue.HashKey(int(pw.seq)%pw.queueCount), timeSeries...)
	}
	return nil
}

func (pw *PromWriter) Close() {
	pw.closed = true
	pw.cancel()
}

func (pw *PromWriter) loopConsume(queueId int) {
	batch := make([]prompb.TimeSeries, 0, pw.conf.BatchSize)
	releaseCache := make([]*prompb.TimeSeries, 0, pw.conf.BatchSize)
	doReq := func() {
		if len(batch) == 0 {
			return
		}
		if err := pw.sendRequest(&prompb.WriteRequest{Timeseries: batch}); err != nil {
			if pw.counter.SendFailedCount == 0 {
				log.Warningf("failed to send promrw request, err: %v", err)
			}
			pw.counter.SendFailedCount++
		} else {
			pw.counter.SendSucceedCount++
			pw.counter.SendTimeSeriesCount += int64(len(batch))
		}
		batch = batch[:0]
		for _, ts := range releaseCache {
			ReleasePrompbTimeSeries(ts)
		}
		releaseCache = releaseCache[:0]
	}

	queueTimeSeries := make([]interface{}, QUEUE_BATCH_SIZE)
	for !pw.closed {
		n := pw.queues.Gets(queue.HashKey(queueId), queueTimeSeries)
		for _, value := range queueTimeSeries[:n] {
			if value == nil {
				doReq()
				continue
			}
			if ts, ok := value.(*prompb.TimeSeries); ok {
				batch = append(batch, *ts)
				releaseCache = append(releaseCache, ts)
				if len(batch) >= pw.conf.BatchSize {
					doReq()
				}
			} else {
				log.Warningf("get prom remote write queue data type wrong")
			}
		}
	}
}

func (pw *PromWriter) sendRequest(wr *prompb.WriteRequest) error {
	data, err := proto.Marshal(wr)
	if err != nil {
		return err
	}
	buf := make([]byte, len(data), cap(data))
	compressedData := snappy.Encode(buf, data)

	req, err := http.NewRequestWithContext(pw.ctx, "POST", pw.conf.Endpoint, bytes.NewReader(compressedData))
	if err != nil {
		return err
	}

	// Add necessary headers specified by:
	// https://cortexmetrics.io/docs/apis/#remote-api
	req.Header.Add("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	// inject extra headers
	for k, v := range pw.conf.Headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 5xx errors are recoverable and the writer should retry?
	// Reference for different behavior according to status code:
	// https://github.com/prometheus/prometheus/pull/2552/files#diff-ae8db9d16d8057358e49d694522e7186
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
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
