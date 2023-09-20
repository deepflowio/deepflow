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

package decoder

import (
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	"github.com/prometheus/common/model"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/config"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type SlowCounter struct {
	// count the number of TimeSeries (not Samples)
	TimeSeriesIn   int64 `statsd:"time-series-in"`
	TimeSeriesErr  int64 `statsd:"time-series-err"`
	TimeSeriesDrop int64 `statsd:"time-series-drop"`
	TimeSeriesOut  int64 `statsd:"time-series-out"`

	SampleOut    int64 `statsd:"sample-out"` // count the number of Samples (not TimeSeries)
	RequestCount int64 `statsd:"request-count"`
}

type SlowItem struct {
	vtapId       uint16
	podClusterId uint16
	ts           prompb.TimeSeries
}

var slowItemPool = pool.NewLockFreePool(func() interface{} {
	return &SlowItem{}
})

func AcquireSlowItem(vtapId, podClusterId uint16, ts *prompb.TimeSeries, extraLabels []prompb.Label) *SlowItem {
	s := slowItemPool.Get().(*SlowItem)
	s.vtapId = podClusterId
	s.podClusterId = podClusterId

	for _, l := range append(extraLabels, ts.Labels...) {
		s.ts.Labels = append(s.ts.Labels, prompb.Label{
			// ts *prompb.TimeSeries is from temporary memory, so needs to be cloned
			Name:  strings.Clone(l.Name),
			Value: strings.Clone(l.Value),
		})
	}

	s.ts.Samples = append(s.ts.Samples, ts.Samples...)
	return s
}

func ReleaseSlowItem(s *SlowItem) {
	if s.ts.Labels != nil {
		s.ts.Labels = s.ts.Labels[:0]
	}
	if s.ts.Samples != nil {
		s.ts.Samples = s.ts.Samples[:0]
	}
	slowItemPool.Put(s)
}

type SlowDecoder struct {
	index            int
	inQueue          queue.QueueReader
	debugEnabled     bool
	config           *config.Config
	prometheusWriter *dbwriter.PrometheusWriter

	samplesBuilder *PrometheusSamplesBuilder
	labelTable     *PrometheusLabelTable

	counter *SlowCounter
	utils.Closable
}

func NewSlowDecoder(
	index int,
	platformData *grpc.PlatformInfoTable,
	prometheusLabelTable *PrometheusLabelTable,
	inQueue queue.QueueReader,
	prometheusWriter *dbwriter.PrometheusWriter,
	config *config.Config,
) *SlowDecoder {
	return &SlowDecoder{
		index:            index,
		samplesBuilder:   NewPrometheusSamplesBuilder("slow-prometheus-builder", index, platformData, prometheusLabelTable, config.AppLabelColumnIncrement, config.IgnoreUniversalTag),
		labelTable:       prometheusLabelTable,
		inQueue:          inQueue,
		debugEnabled:     log.IsEnabledFor(logging.DEBUG),
		prometheusWriter: prometheusWriter,
		config:           config,
		counter:          &SlowCounter{},
	}
}

func (d *SlowDecoder) GetCounter() interface{} {
	var counter *SlowCounter
	counter, d.counter = d.counter, &SlowCounter{}
	return counter
}

func (d *SlowDecoder) Run() {
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": "slow_prometheus"})
	batchSize := d.config.LabelRequestMetricBatchCount
	buffer := make([]interface{}, batchSize)
	req := &trident.PrometheusLabelRequest{}
	slowItems := make([]*SlowItem, 0, batchSize)
	queueTicker := 0
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				queueTicker++
				continue
			}
			d.counter.TimeSeriesIn++
			slowItem, ok := buffer[i].(*SlowItem)
			if !ok {
				continue
			}
			slowItems = append(slowItems, slowItem)
			metricLabelReq, targetReq := d.TimeSeriesToLableIDRequest(&slowItem.ts, slowItem.podClusterId)
			addMetricLabelRequest(req, metricLabelReq)
			addTargetRequest(req, targetReq)
		}

		if len(slowItems) < batchSize && queueTicker == 0 {
			continue
		}

		if len(req.GetRequestLabels()) > 0 || len(req.GetRequestTargets()) > 0 {
			d.labelTable.RequestLabelIDs(req)
			d.counter.RequestCount++
		}

		for _, item := range slowItems {
			d.sendPrometheusSamples(item.vtapId, item.podClusterId, &item.ts)
			ReleaseSlowItem(item)
		}
		req.RequestLabels = req.RequestLabels[:0]
		req.RequestTargets = req.RequestTargets[:0]
		slowItems = slowItems[:0]
		queueTicker = 0
	}
}

func addLabel(req *trident.MetricLabelRequest, name, value string) {
	req.Labels = append(req.Labels,
		&trident.LabelRequest{
			Name:  proto.String(name),
			Value: proto.String(value),
		})
}

func isLabelRequestEqual(l, r *trident.LabelRequest) bool {
	return l.GetName() == r.GetName() && l.GetValue() == r.GetValue()
}

func isMetricLabelRequestEqual(l, r *trident.MetricLabelRequest) bool {
	if len(l.Labels) != len(r.Labels) {
		return false
	}

	if l.GetMetricName() != r.GetMetricName() {
		return false
	}

	for i := range l.Labels {
		if !isLabelRequestEqual(l.Labels[i], r.Labels[i]) {
			return false
		}

	}
	return true
}

func addMetricLabelRequest(req *trident.PrometheusLabelRequest, metricLabel *trident.MetricLabelRequest) {
	if metricLabel.GetMetricName() == "" {
		return
	}

	for _, r := range req.RequestLabels {
		if isMetricLabelRequestEqual(r, metricLabel) {
			return
		}
	}
	req.RequestLabels = append(req.RequestLabels, metricLabel)
}

func isTargetRequestEqual(l, r *trident.TargetRequest) bool {
	return l.GetJob() == r.GetJob() && l.GetInstance() == r.GetInstance()
}

func addTargetRequest(req *trident.PrometheusLabelRequest, target *trident.TargetRequest) {
	if target.GetJob() == "" && target.GetInstance() == "" {
		return
	}

	for _, r := range req.RequestTargets {
		if isTargetRequestEqual(r, target) {
			return
		}
	}
	req.RequestTargets = append(req.RequestTargets, target)
}

func (d *SlowDecoder) TimeSeriesToLableIDRequest(ts *prompb.TimeSeries, podClusterId uint16) (*trident.MetricLabelRequest, *trident.TargetRequest) {
	labelReq := &trident.MetricLabelRequest{}
	targetReq := &trident.TargetRequest{}
	var metricId uint32
	hasMetricId := false

	labelReq.PodClusterId = proto.Uint32(uint32(podClusterId))
	// first, get metric
	for _, l := range ts.Labels {
		if l.Name == model.MetricNameLabel {
			labelReq.MetricName = proto.String(l.Value)
			metricId, hasMetricId = d.labelTable.QueryMetricID(l.Value)
			break
		}
	}

	job, instance := "", ""
	for _, l := range ts.Labels {
		if l.Name == model.MetricNameLabel {
			continue
		} else if l.Name == model.JobLabel {
			job = l.Value
			addLabel(labelReq, l.Name, l.Value)
			continue
		} else if l.Name == model.InstanceLabel {
			instance = l.Value
			addLabel(labelReq, l.Name, l.Value)
			continue
		}
		// if not have matricId, add all label request
		if !hasMetricId {
			addLabel(labelReq, l.Name, l.Value)
			continue
		}

		valueId, ok := d.labelTable.QueryLabelValueID(l.Value)
		if !ok {
			addLabel(labelReq, l.Name, l.Value)
			continue
		}
		nameId, ok := d.labelTable.QueryLabelNameID(l.Name)
		if !ok {
			addLabel(labelReq, l.Name, l.Value)
			continue
		}

		if !d.labelTable.QueryLabelNameValue(nameId, valueId) {
			addLabel(labelReq, l.Name, l.Value)
			continue
		}

		if _, ok := d.labelTable.QueryColumnIndex(metricId, nameId); !ok {
			addLabel(labelReq, l.Name, l.Value)
		}
	}
	if job == "" {
		addLabel(labelReq, model.JobLabel, "")
	}
	if instance == "" {
		addLabel(labelReq, model.InstanceLabel, "")
	}

	instanceId, hasInstanceId := d.labelTable.QueryLabelValueID(instance)
	if !hasInstanceId {
		targetReq.Job = proto.String(job)
		targetReq.Instance = proto.String(instance)
		targetReq.PodClusterId = proto.Uint32(uint32(podClusterId))
		return labelReq, targetReq
	}

	jobId, hasJobId := d.labelTable.QueryLabelValueID(job)
	if !hasJobId {
		targetReq.Job = proto.String(job)
		targetReq.Instance = proto.String(instance)
		targetReq.PodClusterId = proto.Uint32(uint32(podClusterId))
		return labelReq, targetReq
	}

	if _, hasTargetId := d.labelTable.QueryTargetID(podClusterId, jobId, instanceId); !hasTargetId {
		targetReq.Job = proto.String(job)
		targetReq.Instance = proto.String(instance)
		targetReq.PodClusterId = proto.Uint32(uint32(podClusterId))
	}
	return labelReq, targetReq
}

func (d *SlowDecoder) sendPrometheusSamples(vtapID, podClusterId uint16, ts *prompb.TimeSeries) {
	if d.debugEnabled {
		log.Debugf("slow decoder %d vtap %d recv promtheus timeseries: %v", d.index, vtapID, ts)
	}
	isSlowItem, err := d.samplesBuilder.TimeSeriesToStore(vtapID, podClusterId, ts, nil)
	if err != nil {
		if d.counter.TimeSeriesErr == 0 {
			log.Warning(err)
		}
		d.counter.TimeSeriesErr++
		return
	}
	if isSlowItem {
		if d.counter.TimeSeriesDrop == 0 {
			log.Warningf("drop prometheus time series: %s", ts)
		}
		d.counter.TimeSeriesDrop++
		return
	}
	d.prometheusWriter.WriteBatch(d.samplesBuilder.samplesBuffer,
		d.samplesBuilder.metricName,
		d.samplesBuilder.timeSeriesBuffer,
		nil,
		d.samplesBuilder.tsLabelNameIDsBuffer, d.samplesBuilder.tsLabelValueIDsBuffer)
	d.counter.SampleOut += int64(len(d.samplesBuilder.samplesBuffer))
	d.counter.TimeSeriesOut++
}
