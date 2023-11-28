/*
 * Copyright (c) 2023 Yunshan Networks
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
	"net/http"
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
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("flow_metrics.dbwriter")

const (
	CACHE_SIZE = 10240

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
	tables := zerodoc.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, clusterName, storagePolicy, flowMetricsTtl.VtapFlow1M, flowMetricsTtl.VtapFlow1S, flowMetricsTtl.VtapApp1M, flowMetricsTtl.VtapApp1S, coldStorages)
	for _, table := range tables {
		counterName := "metrics_1m"
		if table.ID >= uint8(zerodoc.VTAP_FLOW_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_FLOW_EDGE_PORT_1S) {
			counterName = "metrics_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1S) {
			counterName = "app_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1M) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1M) {
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
	caches := [zerodoc.VTAP_TABLE_ID_MAX][]interface{}{}
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

// PromWriter 是 prom remotewrite 的 db.Writer 实现，负责将 metrics 数据推送给到服务端
type PromWriter struct {
	ctx    context.Context
	cancel context.CancelFunc

	conf   config.PromWriterConfig
	client *http.Client
	queue  chan []prompb.TimeSeries
	filter map[string]struct{}
}

func NewPromWriter(conf config.PromWriterConfig) *PromWriter {
	ctx, cancel := context.WithCancel(context.Background())
	filter := make(map[string]struct{})
	for _, m := range conf.MetricsFilter {
		filter[m] = struct{}{}
	}
	pw := &PromWriter{
		ctx:    ctx,
		cancel: cancel,
		conf:   conf,
		client: &http.Client{Timeout: time.Second * 10},
		queue:  make(chan []prompb.TimeSeries, conf.Concurrency),
		filter: filter,
	}

	for i := 0; i < conf.Concurrency; i++ {
		go pw.loopConsume()
	}
	return pw
}

func (pw *PromWriter) Put(items ...interface{}) error {
	var timeseries []prompb.TimeSeries
	t := time.Now().UnixMicro()

	for _, item := range items {
		doc, ok := item.(*app.Document)
		if !ok {
			log.Warningf("receive wrong type data %v", item)
			continue
		}

		var metrics map[string]float64
		// TODO: 其余 metrics 类型待实现
		if doc.Meter != nil {
			switch meter := doc.Meter.(type) {
			case *zerodoc.AppMeter:
				if _, ok := pw.filter[metricsFilterApp]; ok {
					metrics = zerodoc.EncodeAppMeterToMetrics(meter)
				}
			}
		}

		// 无指标则不匹配 labels
		if len(metrics) <= 0 {
			continue
		}

		var labels []prompb.Label
		if doc.Tagger != nil {
			switch tag := doc.Tagger.(type) {
			case *zerodoc.MiniTag:
				labels = zerodoc.EncodeMiniTagToPromLabels(tag)
			case *zerodoc.CustomTag:
				labels = zerodoc.EncodeCustomTagToPromLabels(tag)
			case *zerodoc.Tag:
				labels = zerodoc.EncodeTagToPromLabels(tag)
			}
		}

		for metric, value := range metrics {
			lbs := pw.copyPromLabels(labels)
			lbs = append(lbs, prompb.Label{
				Name:  "__name__",
				Value: metric,
			})

			timeseries = append(timeseries, prompb.TimeSeries{
				Labels:  lbs,
				Samples: []prompb.Sample{{Value: value, Timestamp: t}},
			})
		}
	}

	if len(timeseries) > 0 {
		pw.queue <- timeseries
	}
	return nil
}

func (pw *PromWriter) Close() {
	pw.cancel()
}

func (pw *PromWriter) copyPromLabels(src []prompb.Label) []prompb.Label {
	n := len(src)
	if n <= 0 {
		return nil
	}

	dst := make([]prompb.Label, 0, n)
	for i := 0; i < len(src); i++ {
		lb := src[i]
		dst = append(dst, prompb.Label{
			Name:  lb.Name,
			Value: lb.Value,
		})
	}
	return dst
}

func (pw *PromWriter) loopConsume() {
	ticker := time.NewTicker(time.Duration(pw.conf.FlushTimeout) * time.Second)
	defer ticker.Stop()

	batch := make([]prompb.TimeSeries, 0, pw.conf.BatchSize)
	doReq := func() {
		if err := pw.sendRequest(&prompb.WriteRequest{Timeseries: batch}); err != nil {
			log.Warningf("failed to send promrw request, err: %v", err)
		}
		batch = make([]prompb.TimeSeries, 0, pw.conf.BatchSize)
	}

	for {
		select {
		case <-pw.ctx.Done():
			return

		case ts := <-pw.queue:
			for _, item := range ts {
				batch = append(batch, item)
				if len(batch) >= pw.conf.BatchSize {
					doReq()
				}
			}

		case <-ticker.C:
			if len(batch) > 0 {
				doReq()
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

	_, err = http.DefaultClient.Do(req)
	return err
}
