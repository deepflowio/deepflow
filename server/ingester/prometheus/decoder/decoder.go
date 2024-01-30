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
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

var log = logging.MustGetLogger("prometheus.decoder")

const (
	BUFFER_SIZE    = 128 // An prometheus message is usually very large, so use a smaller value than usual
	PROMETHEUS_POD = "pod"
)

var appLableValueIDsMaxBuffer []uint32 = make([]uint32, dbwriter.MAX_APP_LABEL_COLUMN_INDEX+1)

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

type PrometheusSamplesBuilder struct {
	name                string
	labelTable          *PrometheusLabelTable
	platformData        *grpc.PlatformInfoTable
	platformDataVersion uint64
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
	podNameIDToUniversalTag  map[uint32]zerodoc.UniversalTag
	instanceIPToUniversalTag map[uint32]zerodoc.UniversalTag
	vtapIDToUniversalTag     map[uint16]zerodoc.UniversalTag

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
		name:                     name,
		platformData:             platformData,
		labelTable:               labelTable,
		podNameIDToUniversalTag:  make(map[uint32]zerodoc.UniversalTag),
		instanceIPToUniversalTag: make(map[uint32]zerodoc.UniversalTag),
		vtapIDToUniversalTag:     make(map[uint16]zerodoc.UniversalTag),
		appLabelColumnAlign:      appLabelColumnAlign,
		ignoreUniversalTag:       ignoreUniversalTag,
		counter:                  &BuilderCounter{},
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

	epcId, podClusterId, err := d.samplesBuilder.GetEpcPodClusterId(vtapID)
	if err != nil {
		if d.counter.TimeSeriesErr == 0 {
			log.Warning(err)
		}
		d.counter.TimeSeriesErr++
		return
	}

	isSlowItem, err := d.samplesBuilder.TimeSeriesToStore(vtapID, epcId, podClusterId, ts, extraLabels)
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
		d.slowDecodeQueue.Put(AcquireSlowItem(vtapID, epcId, podClusterId, ts, extraLabels))
		return
	}
	d.prometheusWriter.WriteBatch(builder.samplesBuffer, builder.metricName, builder.timeSeriesBuffer, extraLabels, builder.tsLabelNameIDsBuffer, builder.tsLabelValueIDsBuffer)
	d.counter.OutCount += int64(len(builder.samplesBuffer))
	d.counter.TimeSeriesOut++
}

func (b *PrometheusSamplesBuilder) GetEpcPodClusterId(vtapID uint16) (uint16, uint16, error) {
	epcId, podClusterId := int32(0), uint16(0)
	if vtapInfo := b.platformData.QueryVtapInfo(uint32(vtapID)); vtapInfo != nil {
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
func (b *PrometheusSamplesBuilder) TimeSeriesToStore(vtapID, epcId, podClusterId uint16, ts *prompb.TimeSeries, extraLabels []prompb.Label) (bool, error) {
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
	var metricID, maxColumnIndex, podNameID, jobID, instanceID uint32
	var ok bool

	// get metricID first
	for _, l := range ts.Labels {
		if metricName == "" && l.Name == model.MetricNameLabel {
			metricName = l.Value
			b.metricName = metricName
			metricID, ok = b.labelTable.QueryMetricID(metricName)
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
		nameID, ok := b.labelTable.QueryLabelNameID(l.Name)
		if !ok {
			b.counter.NameMiss++
			return true, fmt.Errorf("label name %s miss", l.Name)
		}
		valueID, ok := b.labelTable.QueryLabelValueID(l.Value)
		if !ok {
			b.counter.ValueMiss++
			return true, fmt.Errorf("label value %s miss", l.Value)
		}

		if podName == "" && l.Name == PROMETHEUS_POD {
			podName = l.Value
			podNameID = valueID
		}

		var columnIndex uint32
		if jobID == 0 && l.Name == model.JobLabel {
			jobID = valueID
		} else if instanceID == 0 && l.Name == model.InstanceLabel {
			instance = l.Value
			instanceID = valueID
		} else {
			columnIndex, ok = b.labelTable.QueryColumnIndex(metricID, nameID)
			if !ok {
				b.counter.ColumnMiss++
				return true, fmt.Errorf("column metric(%s) id(%d) label name(%s) id(%d) index miss", metricName, metricID, l.Name, nameID)
			}
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

	if jobID == 0 {
		if jobID, ok = b.labelTable.QueryLabelValueID(""); !ok {
			b.counter.ValueMiss++
			return true, fmt.Errorf("label job %s miss", l.Value)
		}
	}
	if instanceID == 0 {
		if instanceID, ok = b.labelTable.QueryLabelValueID(""); !ok {
			b.counter.ValueMiss++
			return true, fmt.Errorf("label instance %s miss", l.Value)
		}
	}
	targetID, ok := b.labelTable.QueryTargetID(epcId, podClusterId, jobID, instanceID)
	if !ok {
		b.counter.TargetMiss++
		return true, fmt.Errorf("target epcId(%d) pod cluster id(%d),jobID(%d),instanceID(%d) miss", epcId, podClusterId, jobID, instanceID)
	}

	if !b.labelTable.QueryMetricTargetPair(metricID, targetID) {
		b.counter.MetricTargetMiss++
		return true, fmt.Errorf("metric target pair metricID(%d),targetID(%d) miss", metricID, targetID)
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

	var universalTag *zerodoc.UniversalTag
	for i, s := range ts.Samples {
		v := float64(s.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}

		if b.ignoreUniversalTag {
			m := dbwriter.AcquirePrometheusSampleMini()
			m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
			m.MetricID = metricID
			m.TargetID = targetID
			m.AppLabelValueIDs = append(m.AppLabelValueIDs, b.appLabelValueIDsBuffer...)
			m.Value = v
			b.samplesBuffer = append(b.samplesBuffer, m)
		} else {
			m := dbwriter.AcquirePrometheusSample()
			m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
			m.MetricID = metricID
			m.TargetID = targetID
			m.AppLabelValueIDs = append(m.AppLabelValueIDs, b.appLabelValueIDsBuffer...)
			m.Value = v

			if i == 0 {
				b.fillUniversalTag(m, vtapID, podName, instance, podNameID, instanceID, false)
				universalTag = &m.UniversalTag
			} else {
				// all samples share the same universal tag
				m.UniversalTag = *universalTag
			}
			b.samplesBuffer = append(b.samplesBuffer, m)
		}

		b.counter.Sample++
	}
	return false, nil
}

func (b *PrometheusSamplesBuilder) fillUniversalTag(m *dbwriter.PrometheusSample, vtapID uint16, podName, instance string, podNameID, instanceID uint32, fillWithVtapId bool) {
	// fast path
	platformDataVersion := b.platformData.Version()
	if platformDataVersion != b.platformDataVersion {
		if b.platformDataVersion != 0 {
			log.Infof("platform data version in prometheus-decoder changed from %d to %d",
				b.platformDataVersion, platformDataVersion)
		}
		b.platformDataVersion = platformDataVersion
		b.podNameIDToUniversalTag = make(map[uint32]zerodoc.UniversalTag)
		b.instanceIPToUniversalTag = make(map[uint32]zerodoc.UniversalTag)
		b.vtapIDToUniversalTag = make(map[uint16]zerodoc.UniversalTag)
	} else {
		if podNameID != 0 {
			if universalTag, ok := b.podNameIDToUniversalTag[podNameID]; ok {
				m.UniversalTag = universalTag
				return
			}
		} else if instanceID != 0 {
			if universalTag, ok := b.instanceIPToUniversalTag[instanceID]; ok {
				m.UniversalTag = universalTag
				return
			}
		} else if fillWithVtapId {
			if universalTag, ok := b.vtapIDToUniversalTag[vtapID]; ok {
				m.UniversalTag = universalTag
				return
			}
		}
	}

	// slow path
	b.fillUniversalTagSlow(m, vtapID, podName, instance, fillWithVtapId)

	// update fast path
	if podName != "" && podNameID != 0 {
		b.podNameIDToUniversalTag[podNameID] = m.UniversalTag
	} else if instanceID != 0 {
		b.instanceIPToUniversalTag[instanceID] = m.UniversalTag
	} else if fillWithVtapId {
		b.vtapIDToUniversalTag[vtapID] = m.UniversalTag
	}
}

func (b *PrometheusSamplesBuilder) fillUniversalTagSlow(m *dbwriter.PrometheusSample, vtapID uint16, podName, instance string, fillWithVtapId bool) {
	t := &m.UniversalTag
	t.VTAPID = vtapID
	t.L3EpcID = datatype.EPC_FROM_INTERNET
	var ip net.IP
	var hasMatched bool
	if podName != "" {
		podInfo := b.platformData.QueryPodInfo(uint32(vtapID), podName)
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
			t.L3EpcID = b.platformData.QueryVtapEpc0(uint32(vtapID))
			ip = net.ParseIP(instanceIP)
			if ip != nil {
				hasMatched = true
			}
		}
	}

	if !hasMatched && fillWithVtapId {
		t.L3EpcID = b.platformData.QueryVtapEpc0(uint32(vtapID))
		vtapInfo := b.platformData.QueryVtapInfo(uint32(vtapID))
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
		info = b.platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
	} else {
		info = b.platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
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
		t.L3DeviceType = zerodoc.DeviceType(info.DeviceType)
		if t.PodClusterID == 0 {
			t.PodClusterID = uint16(info.PodClusterID)
		}
		if t.PodID == 0 {
			t.PodID = info.PodID
		}

		// if it is just Pod Node, there is no need to match the service
		if common.IsPodServiceIP(t.L3DeviceType, t.PodID, 0) {
			t.ServiceID = b.platformData.QueryService(t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, 0)
		}
		t.AutoInstanceID, t.AutoInstanceType = common.GetAutoInstance(t.PodID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
		t.AutoServiceID, t.AutoServiceType = common.GetAutoService(t.ServiceID, t.PodGroupID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), podGroupType, t.L3EpcID)
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
