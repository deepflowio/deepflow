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

package decoder

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/golang/snappy"
	logging "github.com/op/go-logging"
	"github.com/prometheus/common/model"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/config"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("prometheus.decoder")

const (
	BUFFER_SIZE    = 128 // An prometheus message is usually very large, so use a smaller value than usual
	PROMETHEUS_POD = "pod"
)

var appLableValueIDsMaxBuffer []uint32 = make([]uint32, ckdb.MAX_APP_LABEL_COLUMN_INDEX+1)

type Counter struct {
	InCount        int64 `statsd:"in-count"`
	OutCount       int64 `statsd:"out-count"`
	ErrCount       int64 `statsd:"err-count"`
	TimeSeriesIn   int64 `statsd:"time-series-in"`
	TimeSeriesErr  int64 `statsd:"time-series-err"`
	TimeSeriesSlow int64 `statsd:"time-series-slow"`
	TimeSeriesOut  int64 `statsd:"time-series-out"` // count the number of TimeSeries (not Samples)
}

type BuilderCounter struct {
	TimeSeriesIn      int64 `statsd:"time-series-in"`
	TimeSeriesInvaild int64 `statsd:"time-series-invalid"`
	EpcMiss           int64 `statsd:"epc-miss"`
	LabelCount        int64 `statsd:"label-in"`
	MetricMiss        int64 `statsd:"metirc-miss"`
	NameMiss          int64 `statsd:"name-miss"`
	ValueMiss         int64 `statsd:"value-miss"`
	NameValueMiss     int64 `statsd:"name-value-miss"`
	ColumnMiss        int64 `statsd:"column-miss"`
	TargetMiss        int64 `statsd:"target-miss"`
	MetricTargetMiss  int64 `statsd:"metric-target-miss"`
	Sample            int64 `statsd:"sample-out"`
}

type UniversalTagKey struct {
	L3EpcID    int32
	PodNameID  uint32
	InstanceID uint32
}

type PrometheusSamplesBuilder struct {
	name                string
	labelTable          *PrometheusLabelTable
	platformData        *grpc.PlatformInfoTable
	platformDataVersion [grpc.MAX_ORG_COUNT]uint64
	appLabelColumnAlign int
	ignoreUniversalTag  bool

	// temporary buffers
	metricName              string
	samplesBuffer           []interface{} // store all Samples in a TimeSeries.
	timeSeriesBuffer        *prompb.TimeSeries
	tsLabelNameIDsBuffer    []uint32 // store timeSeries labelNameIDs without metricName
	tsLabelValueIDsBuffer   []uint32 // store timeSeries labelValueIDs without metricID
	labelColumnIndexsBuffer []uint32
	appLabelValueIDsBuffer  []uint32

	// universal tag cache
	cacheUniversalTags [grpc.MAX_ORG_COUNT]map[UniversalTagKey]flow_metrics.UniversalTag

	counter *BuilderCounter
	utils.Closable
}

func (d *PrometheusSamplesBuilder) GetCounter() interface{} {
	var counter *BuilderCounter
	counter, d.counter = d.counter, &BuilderCounter{}
	return counter
}

func NewPrometheusSamplesBuilder(name string, index int, platformData *grpc.PlatformInfoTable, labelTable *PrometheusLabelTable, appLabelColumnAlign int, ignoreUniversalTag bool) *PrometheusSamplesBuilder {
	p := &PrometheusSamplesBuilder{
		name:                name,
		platformData:        platformData,
		labelTable:          labelTable,
		appLabelColumnAlign: appLabelColumnAlign,
		ignoreUniversalTag:  ignoreUniversalTag,
		counter:             &BuilderCounter{},
	}

	for i := 0; i < grpc.MAX_ORG_COUNT; i++ {
		p.cacheUniversalTags[i] = make(map[UniversalTagKey]flow_metrics.UniversalTag)
	}

	common.RegisterCountableForIngester("decoder", p, stats.OptionStatTags{
		"thread":   strconv.Itoa(index),
		"msg_type": name})
	return p
}

type Decoder struct {
	index            int
	inQueue          queue.QueueReader
	slowDecodeQueue  queue.QueueWriter
	prometheusWriter *dbwriter.PrometheusWriter
	debugEnabled     bool
	config           *config.Config

	orgId, teamId uint16

	samplesBuilder *PrometheusSamplesBuilder

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int,
	platformData *grpc.PlatformInfoTable,
	prometheusLabelTable *PrometheusLabelTable,
	inQueue queue.QueueReader,
	slowDecodeQueue queue.QueueWriter,
	prometheusWriter *dbwriter.PrometheusWriter,
	config *config.Config,
) *Decoder {
	return &Decoder{
		index:            index,
		samplesBuilder:   NewPrometheusSamplesBuilder("prometheus-builder", index, platformData, prometheusLabelTable, config.AppLabelColumnIncrement, config.IgnoreUniversalTag),
		inQueue:          inQueue,
		slowDecodeQueue:  slowDecodeQueue,
		debugEnabled:     log.IsEnabledFor(logging.DEBUG),
		prometheusWriter: prometheusWriter,
		config:           config,
		counter:          &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": datatype.MESSAGE_TYPE_PROMETHEUS.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	promWriteRequest := &prompb.WriteRequest{}
	decodeBuffer := []byte{}
	decoder := &codec.SimpleDecoder{}
	prometheusMetric := &pb.PrometheusMetric{}
	extraLabels := &[]prompb.Label{}
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				continue
			}
			d.counter.InCount++
			recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
			if !ok {
				log.Warning("get decode queue data type wrong")
				continue
			}
			decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
			d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
			d.handlePrometheusData(recvBytes.VtapID, decoder, &decodeBuffer, promWriteRequest, prometheusMetric, extraLabels)
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func DecodeWriteRequest(compressed []byte, decodeBuffer *[]byte, req *prompb.WriteRequest) error {
	decodeData, err := snappy.Decode(*decodeBuffer, compressed)
	if err != nil {
		return err
	}

	if err := req.Unmarshal(decodeData); err != nil {
		return err
	}

	if len(decodeData) > len(*decodeBuffer) {
		*decodeBuffer = decodeData
	}

	return nil
}

func prometheusMetricReset(m *pb.PrometheusMetric) {
	m.Metrics = m.Metrics[:0]
	m.ExtraLabelNames = m.ExtraLabelNames[:0]
	m.ExtraLabelValues = m.ExtraLabelValues[:0]
}

func (d *Decoder) handlePrometheusData(vtapID uint16, decoder *codec.SimpleDecoder, decodeBuffer *[]byte, req *prompb.WriteRequest, prometheusMetric *pb.PrometheusMetric, extraLabels *[]prompb.Label) {
	for !decoder.IsEnd() {
		prometheusMetricReset(prometheusMetric)
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrCount == 0 {
				log.Errorf("prometheus decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrCount++
			return
		}

		if err := prometheusMetric.Unmarshal(bytes); err != nil {
			if d.counter.ErrCount == 0 {
				log.Warningf("prometheus metric parse failed, err msg: %s", err)
			}
			d.counter.ErrCount++
			continue
		}

		err := DecodeWriteRequest(prometheusMetric.Metrics, decodeBuffer, req)
		if err != nil {
			if d.counter.ErrCount == 0 {
				log.Warningf("prometheus parse failed, err msg:%s", err)
			}
			d.counter.ErrCount++
			continue
		}

		*extraLabels = (*extraLabels)[:0]
		for i := range prometheusMetric.ExtraLabelNames {
			*extraLabels = append(*extraLabels, prompb.Label{
				Name:  prometheusMetric.ExtraLabelNames[i],
				Value: prometheusMetric.ExtraLabelValues[i],
			})
		}

		for i := range req.Timeseries {
			d.counter.TimeSeriesIn++
			d.sendPrometheus(vtapID, &req.Timeseries[i], *extraLabels)
		}
		req.ResetWithBufferReserved() // release memory as soon as possible
	}
}

func (d *Decoder) sendPrometheus(vtapID uint16, ts *prompb.TimeSeries, extraLabels []prompb.Label) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv promtheus timeseries: %v", d.index, vtapID, ts)
	}

	epcId, podClusterId, err := d.samplesBuilder.GetEpcPodClusterId(d.orgId, vtapID)
	if err != nil {
		if d.counter.TimeSeriesErr == 0 {
			log.Warning(err)
		}
		d.counter.TimeSeriesErr++
		return
	}

	isSlowItem, err := d.samplesBuilder.TimeSeriesToStore(vtapID, epcId, podClusterId, d.orgId, d.teamId, ts, extraLabels)
	if !isSlowItem && err != nil {
		if d.counter.TimeSeriesErr == 0 {
			log.Warning(err)
		}
		d.counter.TimeSeriesErr++
		return
	}
	builder := d.samplesBuilder
	if isSlowItem {
		d.counter.TimeSeriesSlow++
		orgId, teamId := d.orgId, d.teamId
		d.slowDecodeQueue.Put(AcquireSlowItem(vtapID, epcId, podClusterId, orgId, teamId, ts, extraLabels))
		return
	}
	d.prometheusWriter.WriteBatch(builder.samplesBuffer, builder.metricName, builder.timeSeriesBuffer, extraLabels, builder.tsLabelNameIDsBuffer, builder.tsLabelValueIDsBuffer)
	d.counter.OutCount += int64(len(builder.samplesBuffer))
	d.counter.TimeSeriesOut++
}

func (b *PrometheusSamplesBuilder) GetEpcPodClusterId(orgId, vtapID uint16) (uint16, uint16, error) {
	epcId, podClusterId := int32(0), uint16(0)
	if vtapInfo := b.platformData.QueryVtapInfo(orgId, vtapID); vtapInfo != nil {
		epcId, podClusterId = vtapInfo.EpcId, uint16(vtapInfo.PodClusterId)
	}
	if epcId == 0 || epcId == datatype.EPC_FROM_INTERNET {
		b.counter.EpcMiss++
		return 0, 0, fmt.Errorf("can't get the epc id of vtap(%d)", vtapID)
	}
	return uint16(epcId), podClusterId, nil
}

// if success,return false,nil
// if failed, return false,err
// if isSlow, return true,slowReason
func (b *PrometheusSamplesBuilder) TimeSeriesToStore(vtapID, epcId, podClusterId, orgId, teamID uint16, ts *prompb.TimeSeries, extraLabels []prompb.Label) (bool, error) {
	if len(ts.Samples) == 0 {
		b.counter.TimeSeriesInvaild++
		return false, fmt.Errorf("prometheum samples of time serries(%s) is empty.", ts)
	}
	b.counter.TimeSeriesIn++

	b.samplesBuffer = b.samplesBuffer[:0]
	b.timeSeriesBuffer = ts
	b.tsLabelNameIDsBuffer = b.tsLabelNameIDsBuffer[:0]
	b.tsLabelValueIDsBuffer = b.tsLabelValueIDsBuffer[:0]
	b.labelColumnIndexsBuffer = b.labelColumnIndexsBuffer[:0]
	b.appLabelValueIDsBuffer = b.appLabelValueIDsBuffer[:0]

	metricName, podName, instance := "", "", ""
	var metricID, maxColumnIndex, podNameID, instanceID uint32
	var ok bool

	// get metricID first
	for _, l := range ts.Labels {
		if metricName == "" && l.Name == model.MetricNameLabel {
			metricName = l.Value
			b.metricName = metricName
			metricID, ok = b.labelTable.QueryMetricID(orgId, metricName)
			if !ok {
				b.counter.MetricMiss++
				return true, fmt.Errorf("metric name %s miss", metricName)
			}
			break
		}
	}

	metricHasSkipped := false
	var l *prompb.Label
	tsLen, extraLen := len(ts.Labels), len(extraLabels)
	for i := 0; i < tsLen+extraLen; i++ {
		if i < tsLen {
			l = &ts.Labels[i]
		} else {
			l = &extraLabels[i-tsLen]
		}
		if !metricHasSkipped && l.Name == model.MetricNameLabel {
			metricHasSkipped = true
			continue
		}
		b.counter.LabelCount++
		nameID, ok := b.labelTable.QueryLabelNameID(orgId, l.Name)
		if !ok {
			b.counter.NameMiss++
			return true, fmt.Errorf("label name %s miss", l.Name)
		}
		valueID, ok := b.labelTable.QueryLabelValueID(orgId, l.Value)
		if !ok {
			b.counter.ValueMiss++
			return true, fmt.Errorf("label value %s miss", l.Value)
		}

		// the Controller needs to get all the Value lists contained in the Name for filtering when querying
		if !b.labelTable.QueryLabelNameValue(orgId, nameID, valueID) {
			b.counter.NameValueMiss++
			return true, fmt.Errorf("label name(%s) id(%d) value(%s) id(%d) miss", l.Name, nameID, l.Value, valueID)
		}

		if podName == "" && l.Name == PROMETHEUS_POD {
			podName = l.Value
			podNameID = valueID
		} else if instanceID == 0 && l.Name == model.InstanceLabel {
			instance = l.Value
			instanceID = valueID
		}

		columnIndex, ok := b.labelTable.QueryColumnIndex(orgId, metricID, nameID)
		if !ok {
			b.counter.ColumnMiss++
			return true, fmt.Errorf("column metric(%s) id(%d) label name(%s) id(%d) index miss", metricName, metricID, l.Name, nameID)
		}

		b.labelColumnIndexsBuffer = append(b.labelColumnIndexsBuffer, columnIndex)
		b.tsLabelNameIDsBuffer = append(b.tsLabelNameIDsBuffer, nameID)
		b.tsLabelValueIDsBuffer = append(b.tsLabelValueIDsBuffer, valueID)
		if maxColumnIndex < columnIndex {
			maxColumnIndex = columnIndex
		}
	}

	if metricName == "" {
		b.counter.TimeSeriesInvaild++
		return false, fmt.Errorf("prometheum metric name(%s) is empty", metricName)
	}

	b.appLabelValueIDsBuffer = append(b.appLabelValueIDsBuffer,
		// aligned by b.appLabelColumnAlign
		appLableValueIDsMaxBuffer[:(int(maxColumnIndex)+(b.appLabelColumnAlign-1))/b.appLabelColumnAlign*b.appLabelColumnAlign+1]...)

	for i, index := range b.labelColumnIndexsBuffer {
		// target label index is 0
		if index == 0 {
			continue
		}
		b.appLabelValueIDsBuffer[index] = b.tsLabelValueIDsBuffer[i]
	}

	var universalTag *flow_metrics.UniversalTag
	for i, s := range ts.Samples {
		v := float64(s.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}

		if b.ignoreUniversalTag {
			m := dbwriter.AcquirePrometheusSampleMini()
			m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
			m.MetricID = metricID
			m.AppLabelValueIDs = append(m.AppLabelValueIDs, b.appLabelValueIDsBuffer...)
			m.Value = v
			m.VtapId = vtapID
			b.samplesBuffer = append(b.samplesBuffer, m)
			m.OrgId, m.TeamID = orgId, teamID
		} else {
			m := dbwriter.AcquirePrometheusSample()
			m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
			m.MetricID = metricID
			m.AppLabelValueIDs = append(m.AppLabelValueIDs, b.appLabelValueIDsBuffer...)
			m.Value = v
			m.VtapId = vtapID
			m.OrgId, m.TeamID = orgId, teamID

			if i == 0 {
				b.fillUniversalTag(m, vtapID, podName, instance, podNameID, instanceID, false)
				universalTag = &m.UniversalTag
			} else {
				if universalTag != nil {
					// all samples share the same universal tag
					m.UniversalTag = *universalTag
				} else {
					b.fillUniversalTag(m, vtapID, podName, instance, podNameID, instanceID, false)
				}
			}
			b.samplesBuffer = append(b.samplesBuffer, m)
		}

		b.counter.Sample++
	}
	return false, nil
}

func (b *PrometheusSamplesBuilder) fillUniversalTag(m *dbwriter.PrometheusSample, vtapID uint16, podName, instance string, podNameID, instanceID uint32, fillWithVtapId bool) {
	platformDataVersion := b.platformData.Version(m.OrgId)
	if platformDataVersion != b.platformDataVersion[m.OrgId] {
		if b.platformDataVersion[m.OrgId] != 0 {
			log.Infof("platform data version in prometheus-decoder changed from %d to %d",
				b.platformDataVersion[m.OrgId], platformDataVersion)
		}
		b.platformDataVersion[m.OrgId] = platformDataVersion
		b.cacheUniversalTags[m.OrgId] = make(map[UniversalTagKey]flow_metrics.UniversalTag)
	} else {
		// fast path
		l3EpcID := b.platformData.QueryVtapEpc0(m.OrgId, vtapID)
		if universalTag, ok := b.cacheUniversalTags[m.OrgId][UniversalTagKey{
			L3EpcID:    l3EpcID,
			PodNameID:  podNameID,
			InstanceID: instanceID,
		}]; ok {
			m.UniversalTag = universalTag
			return
		}
	}

	// slow path
	b.fillUniversalTagSlow(m, vtapID, podName, instance, fillWithVtapId)
	// update fast path
	b.cacheUniversalTags[m.OrgId][UniversalTagKey{
		L3EpcID:    m.UniversalTag.L3EpcID,
		PodNameID:  podNameID,
		InstanceID: instanceID,
	}] = m.UniversalTag
}

func (b *PrometheusSamplesBuilder) fillUniversalTagSlow(m *dbwriter.PrometheusSample, vtapID uint16, podName, instance string, fillWithVtapId bool) {
	t := &m.UniversalTag
	t.VTAPID = vtapID
	t.L3EpcID = b.platformData.QueryVtapEpc0(m.OrgId, vtapID)
	var ip net.IP
	var hasMatched bool
	if podName != "" {
		podInfo := b.platformData.QueryPodInfo(m.OrgId, vtapID, podName)
		if podInfo != nil {
			t.PodClusterID = uint16(podInfo.PodClusterId)
			t.PodID = podInfo.PodId
			t.L3EpcID = podInfo.EpcId
			ip = net.ParseIP(podInfo.Ip)
			// maybe Pod is hostnetwork mode or can't get pod IP, then get pod node IP instead
			if ip == nil {
				ip = net.ParseIP(podInfo.PodNodeIp)
			}
			hasMatched = true
		}
	}

	if !hasMatched {
		if instanceIP := getIPPartFromPrometheusInstanceString(instance); instanceIP != "" {
			ip = net.ParseIP(instanceIP)
			if ip != nil {
				hasMatched = true
			}
		}
	}

	if !hasMatched && fillWithVtapId {
		vtapInfo := b.platformData.QueryVtapInfo(m.OrgId, vtapID)
		if vtapInfo != nil {
			ip = net.ParseIP(vtapInfo.Ip)
			t.PodClusterID = uint16(vtapInfo.PodClusterId)
			hasMatched = true
		}
	}

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			t.IsIPv6 = 0
			t.IP = utils.IpToUint32(ip4)
		} else {
			t.IsIPv6 = 1
			t.IP6 = ip
		}
	}

	var info *grpc.Info
	if t.IsIPv6 == 1 {
		info = b.platformData.QueryIPV6Infos(m.OrgId, t.L3EpcID, t.IP6)
	} else {
		info = b.platformData.QueryIPV4Infos(m.OrgId, t.L3EpcID, t.IP)
	}
	podGroupType := uint8(0)
	if info != nil {
		t.RegionID = uint16(info.RegionID)
		t.AZID = uint16(info.AZID)
		t.HostID = uint16(info.HostID)
		t.PodGroupID = info.PodGroupID
		podGroupType = uint8(info.PodGroupType)
		t.PodNSID = uint16(info.PodNSID)
		t.PodNodeID = info.PodNodeID
		t.SubnetID = uint16(info.SubnetID)
		t.L3DeviceID = info.DeviceID
		t.L3DeviceType = flow_metrics.DeviceType(info.DeviceType)
		if t.PodClusterID == 0 {
			t.PodClusterID = uint16(info.PodClusterID)
		}
		if t.PodID == 0 {
			t.PodID = info.PodID
		}

		// if it is just Pod Node, there is no need to match the service
		if common.IsPodServiceIP(t.L3DeviceType, t.PodID, 0) {
			t.ServiceID = b.platformData.QueryPodService(m.OrgId, t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, 0)
		}
		t.AutoInstanceID, t.AutoInstanceType = common.GetAutoInstance(t.PodID, t.GPID, t.PodNodeID, t.L3DeviceID, uint32(t.SubnetID), uint8(t.L3DeviceType), t.L3EpcID)
		customServiceID := b.platformData.QueryCustomService(m.OrgId, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, t.ServiceID, t.PodGroupID, t.L3DeviceID, t.PodID, uint8(t.L3DeviceType))
		t.AutoServiceID, t.AutoServiceType = common.GetAutoService(customServiceID, t.ServiceID, t.PodGroupID, t.GPID, uint32(t.PodClusterID), t.L3DeviceID, uint32(t.SubnetID), uint8(t.L3DeviceType), podGroupType, t.L3EpcID)
	}
}

// get ip part from "192.168.0.1:22" or "[2001:db8::68]:22"
func getIPPartFromPrometheusInstanceString(instance string) string {
	if len(instance) == 0 {
		return instance
	}

	index := strings.LastIndex(instance, ":")
	if index < 0 {
		index = len(instance)
	}
	if instance[0] == '[' {
		if instance[index-1] == ']' {
			return instance[1 : index-1]
		} else {
			return ""
		}
	} else {
		return instance[:index]
	}
}
