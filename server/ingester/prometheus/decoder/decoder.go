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

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	logging "github.com/op/go-logging"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/config"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("prometheus.decoder")

const (
	BUFFER_SIZE              = 128 // An prometheus message is usually very large, so use a smaller value than usual
	PROMETHEUS_POD           = "pod"
	VTABLE_PREFIX_PROMETHEUS = "prometheus."
)

type Counter struct {
	InCount        int64 `statsd:"in-count"`
	OutCount       int64 `statsd:"out-count"`
	ErrCount       int64 `statsd:"err-count"`
	TimeSeriesIn   int64 `statsd:"time-series-in"`
	TimeSeriesErr  int64 `statsd:"time-series-err"`
	TimeSeriesSlow int64 `statsd:"time-series-slow"`
	TimeSeriesOut  int64 `statsd:"time-series-out"` // count the number of TimeSeries (not Samples)
}

type BuildCounter struct {
	TimeSeriesIn      int64 `statsd:"time-series-in"`
	TimeSeriesInvaild int64 `statsd:"time-series-invalid"`
	LabelCount        int64 `statsd:"label-in"`
	MetricMiss        int64 `statsd:"metirc-miss"`
	NameMiss          int64 `statsd:"name-miss"`
	ValueMiss         int64 `statsd:"value-miss"`
	ColumnMiss        int64 `statsd:"column-miss"`
	TargetMiss        int64 `statsd:"target-miss"`
	Sample            int64 `statsd:"sample-out"`
}

type BuildPrometheus struct {
	labelTable          *PrometheusLabelTable
	platformData        *grpc.PlatformInfoTable
	platformDataVersion uint64

	// for prometheus, temporary buffers
	prometheusBuffer        []interface{} // store all Samples in a TimeSeries.
	labelNamesBuffer        []string      // store label names in a time series
	labelValuesBuffer       []string      // store label values in a time series
	labelNameIDsBuffer      []uint32
	labelValueIDsBuffer     []uint32
	labelColumnIndexsBuffer []uint32
	appLabelValueIDsBuffer  []uint32
	appLabelColumnAlign     int

	// universal tag cache
	podNameToUniversalTag    map[string]*zerodoc.UniversalTag
	instanceIPToUniversalTag map[string]*zerodoc.UniversalTag
	vtapIDToUniversalTag     map[uint16]*zerodoc.UniversalTag

	counter *BuildCounter
	utils.Closable
}

func (d *BuildPrometheus) GetCounter() interface{} {
	var counter *BuildCounter
	counter, d.counter = d.counter, &BuildCounter{}
	return counter
}

func NewBuildPrometheus(platformData *grpc.PlatformInfoTable, labelTable *PrometheusLabelTable, appLabelColumnAlign int) *BuildPrometheus {
	return &BuildPrometheus{
		platformData:             platformData,
		labelTable:               labelTable,
		podNameToUniversalTag:    make(map[string]*zerodoc.UniversalTag),
		instanceIPToUniversalTag: make(map[string]*zerodoc.UniversalTag),
		vtapIDToUniversalTag:     make(map[uint16]*zerodoc.UniversalTag),
		appLabelColumnAlign:      appLabelColumnAlign,
		counter:                  &BuildCounter{},
	}
}

type Decoder struct {
	index            int
	inQueue          queue.QueueReader
	slowDecodeQueue  queue.QueueWriter
	prometheusWriter *dbwriter.PrometheusWriter
	debugEnabled     bool
	config           *config.Config

	buildPrometheus *BuildPrometheus

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
		buildPrometheus:  NewBuildPrometheus(platformData, prometheusLabelTable, config.AppLabelColumnIncrement),
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
	common.RegisterCountableForIngester("decoder", d.buildPrometheus, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": "prometheus-builder"})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
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
			d.handlePrometheus(recvBytes.VtapID, decoder)
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func DecodeWriteRequest(compressed []byte) (*prompb.WriteRequest, error) {
	reqBuf, err := snappy.Decode(nil, compressed)
	if err != nil {
		return nil, err
	}

	var req prompb.WriteRequest
	if err := proto.Unmarshal(reqBuf, &req); err != nil {
		return nil, err
	}

	return &req, nil
}

func (d *Decoder) handlePrometheus(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		data := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrCount == 0 {
				log.Errorf("prometheus decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrCount++
			return
		}
		req, err := DecodeWriteRequest(data)
		if err != nil {
			if d.counter.ErrCount == 0 {
				log.Warningf("prometheus parse failed, err msg:%s", err)
			}
			d.counter.ErrCount++
		}

		for _, ts := range req.Timeseries {
			d.counter.TimeSeriesIn++
			d.sendPrometheus(vtapID, &ts)
		}
	}
}

func (d *Decoder) sendPrometheus(vtapID uint16, ts *prompb.TimeSeries) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv promtheus timeseries: %v", d.index, vtapID, ts)
	}
	isSlowItem, err := d.buildPrometheus.TimeSeriesToStore(vtapID, ts)
	if err != nil {
		if d.counter.TimeSeriesErr == 0 {
			log.Warning(err)
		}
		d.counter.TimeSeriesErr++
		return
	}
	build := d.buildPrometheus
	if isSlowItem {
		d.counter.TimeSeriesSlow++
		d.slowDecodeQueue.Put(AcquireSlowItem(vtapID, ts))
		return
	}
	d.prometheusWriter.WriteBatch(build.prometheusBuffer, build.labelNamesBuffer, build.labelValuesBuffer)
	d.counter.OutCount += int64(len(build.prometheusBuffer))
	d.counter.TimeSeriesOut++
}

var noMetric, noName, noValue, noColumn, noTarget uint64

func (b *BuildPrometheus) TimeSeriesToStore(vtapID uint16, ts *prompb.TimeSeries) (bool, error) {
	if len(ts.Samples) == 0 {
		b.counter.TimeSeriesInvaild++
		return false, nil
	}
	b.counter.TimeSeriesIn++

	b.prometheusBuffer = b.prometheusBuffer[:0]
	b.labelNamesBuffer = b.labelNamesBuffer[:0]
	b.labelValuesBuffer = b.labelValuesBuffer[:0]
	b.labelNameIDsBuffer = b.labelNameIDsBuffer[:0]
	b.labelValueIDsBuffer = b.labelValueIDsBuffer[:0]
	b.labelColumnIndexsBuffer = b.labelColumnIndexsBuffer[:0]
	b.appLabelValueIDsBuffer = b.appLabelValueIDsBuffer[:0]

	metricName, podName, instance, job := "", "", "", ""
	for _, l := range ts.Labels {
		if l.Name == model.MetricNameLabel {
			metricName = l.Value
			continue
		}
		if l.Name == PROMETHEUS_POD {
			podName = l.Value
		} else if l.Name == model.JobLabel {
			job = l.Value
		} else if l.Name == model.InstanceLabel {
			instance = l.Value
		}
		b.labelNamesBuffer = append(b.labelNamesBuffer, l.Name)
		b.labelValuesBuffer = append(b.labelValuesBuffer, l.Value)
	}

	if metricName == "" || (job == "" && instance == "") {
		b.counter.TimeSeriesInvaild++
		return false, fmt.Errorf("prometheum metric name(%s) or job(%s) and  instance(%s) is empty", metricName, job, instance)
	}

	metricID, ok := b.labelTable.QueryMetricID(metricName)
	if !ok {
		if noMetric%1000 == 0 {
			log.Infof("metric id(%d) not found %s", noMetric, metricName)
		}
		noMetric++
		b.counter.MetricMiss++
		return true, nil
	}
	var maxColumnIndex, jobID, instanceID uint32
	for i, name := range b.labelNamesBuffer {
		b.counter.LabelCount++
		nameID, ok := b.labelTable.QueryNameID(name)
		if !ok {
			b.counter.NameMiss++
			if noName%1000 == 0 {
				log.Infof("name id(%d) not found %s", noName, name)
			}
			noName++
			return true, nil
		}
		valueID, ok := b.labelTable.QueryValueID(b.labelValuesBuffer[i])
		if !ok {
			b.counter.ValueMiss++
			if noValue%1000 == 0 {
				log.Infof("value id(%d) not found %s", noValue, b.labelValuesBuffer[i])
			}
			noValue++
			return true, nil
		}
		var columnIndex uint32
		if name == model.JobLabel {
			jobID = valueID
		} else if name == model.InstanceLabel {
			instanceID = valueID
		}
		columnIndex, ok = b.labelTable.QueryColumnIndex(metricID, nameID)
		if !ok {
			b.counter.ColumnMiss++
			if noColumn%1000 == 0 {
				log.Infof("columnIndex id(%d) not found %s %s %d  %d ", noColumn, metricName, name, metricID, nameID)
			}
			noColumn++
			return true, nil
		}
		b.labelColumnIndexsBuffer = append(b.labelColumnIndexsBuffer, columnIndex)
		b.labelValueIDsBuffer = append(b.labelValueIDsBuffer, valueID)
		if maxColumnIndex < columnIndex {
			maxColumnIndex = columnIndex
		}
	}
	targetID, ok := b.labelTable.QueryTargetID(jobID, instanceID)
	if !ok {
		b.counter.TargetMiss++
		if noTarget%1000 == 0 {
			log.Infof("target id(%d) not found metric:%s job:%s instance:%s  %d %d %d ", noTarget, metricName, job, instance, metricID, jobID, instanceID)
		}
		noTarget++
		return true, nil
	}
	b.appLabelValueIDsBuffer = append(b.appLabelValueIDsBuffer,
		// aligned by b.appLabelColumnAlign
		make([]uint32, (int(maxColumnIndex)+(b.appLabelColumnAlign-1))/b.appLabelColumnAlign*b.appLabelColumnAlign+1)...)

	for i, index := range b.labelColumnIndexsBuffer {
		// target label index is 0
		if index == 0 {
			continue
		}
		b.appLabelValueIDsBuffer[index] = b.labelValueIDsBuffer[i]
	}

	var universalTag *zerodoc.UniversalTag
	for i, s := range ts.Samples {
		m := dbwriter.AcquirePrometheus()
		m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
		m.MetricID = metricID
		m.TargetID = targetID
		m.AppLabelValueIDs = append(m.AppLabelValueIDs, b.appLabelValueIDsBuffer...)

		v := float64(s.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			dbwriter.ReleasePrometheus(m)
			continue
		}
		m.Value = v

		if i == 0 {
			b.fillPrometheusBase(m, vtapID, podName, instance, false)
			universalTag = &m.UniversalTag
		} else {
			// all samples share the same universal tag
			m.UniversalTag = *universalTag
		}
		b.prometheusBuffer = append(b.prometheusBuffer, m)
		b.counter.Sample++
	}
	return false, nil
}

func (b *BuildPrometheus) fillPrometheusBase(m *dbwriter.Prometheus, vtapID uint16, podName, instance string, fillWithVtapId bool) {
	var universalTag *zerodoc.UniversalTag
	var instanceIP string

	// fast path
	platformDataVersion := b.platformData.Version()
	if platformDataVersion != b.platformDataVersion {
		if b.platformDataVersion != 0 {
			log.Infof("platform data version in prometheus-decoder changed from %d to %d",
				b.platformDataVersion, platformDataVersion)
		}
		b.platformDataVersion = platformDataVersion
		b.podNameToUniversalTag = make(map[string]*zerodoc.UniversalTag)
		b.instanceIPToUniversalTag = make(map[string]*zerodoc.UniversalTag)
		b.vtapIDToUniversalTag = make(map[uint16]*zerodoc.UniversalTag)
	} else {
		if podName != "" {
			universalTag, _ = b.podNameToUniversalTag[podName]
		} else if instance != "" {
			instanceIP = getIPPartFromPrometheusInstanceString(instance)
			if instanceIP != "" {
				universalTag, _ = b.instanceIPToUniversalTag[instanceIP]
			}
		} else if fillWithVtapId {
			universalTag, _ = b.vtapIDToUniversalTag[vtapID]
		}
		if universalTag != nil {
			m.UniversalTag = *universalTag
			return
		}
	}

	// slow path
	b.fillPrometheusBaseSlow(m, vtapID, podName, instanceIP, fillWithVtapId)

	// update fast path
	universalTag = &zerodoc.UniversalTag{} // Since the cache dictionary will be cleaned up by GC, no need to use a pool here.
	*universalTag = m.UniversalTag
	if podName != "" {
		b.podNameToUniversalTag[podName] = universalTag
	} else if instanceIP != "" {
		b.instanceIPToUniversalTag[instanceIP] = universalTag
	} else if fillWithVtapId {
		b.vtapIDToUniversalTag[vtapID] = universalTag
	}
}

func (b *BuildPrometheus) fillPrometheusBaseSlow(m *dbwriter.Prometheus, vtapID uint16, podName, instanceIP string, fillWithVtapId bool) {
	t := &m.UniversalTag
	t.VTAPID = vtapID
	t.L3EpcID = datatype.EPC_FROM_INTERNET
	var ip net.IP
	if podName != "" {
		podInfo := b.platformData.QueryPodInfo(uint32(vtapID), podName)
		if podInfo != nil {
			t.PodClusterID = uint16(podInfo.PodClusterId)
			t.PodID = podInfo.PodId
			t.L3EpcID = podInfo.EpcId
			ip = net.ParseIP(podInfo.Ip)
		}
	} else if instanceIP != "" {
		t.L3EpcID = b.platformData.QueryVtapEpc0(uint32(vtapID))
		ip = net.ParseIP(instanceIP)
	} else if fillWithVtapId {
		t.L3EpcID = b.platformData.QueryVtapEpc0(uint32(vtapID))
		vtapInfo := b.platformData.QueryVtapInfo(uint32(vtapID))
		if vtapInfo != nil {
			ip = net.ParseIP(vtapInfo.Ip)
			t.PodClusterID = uint16(vtapInfo.PodClusterId)
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
	} else {
		return
	}

	var info *grpc.Info
	if t.IsIPv6 == 1 {
		info = b.platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
	} else {
		info = b.platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
	}
	if info != nil {
		t.RegionID = uint16(info.RegionID)
		t.AZID = uint16(info.AZID)
		t.HostID = uint16(info.HostID)
		t.PodGroupID = info.PodGroupID
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

		if common.IsPodServiceIP(t.L3DeviceType, t.PodID, t.PodNodeID) {
			t.ServiceID = b.platformData.QueryService(t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, 0)
		}
		t.AutoInstanceID, t.AutoInstanceType = common.GetAutoInstance(t.PodID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
		t.AutoServiceID, t.AutoServiceType = common.GetAutoService(t.ServiceID, t.PodGroupID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
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
