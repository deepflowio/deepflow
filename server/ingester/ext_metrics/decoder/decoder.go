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
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
	mpb "github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

var log = logging.MustGetLogger("ext_metrics.decoder")

const (
	BUFFER_SIZE              = 128 // An ext_metrics message is usually very large, so use a smaller value than usual
	TELEGRAF_POD             = "pod_name"
	PROMETHEUS_POD           = "pod"
	PROMETHEUS_INSTANCE      = "instance"
	VTABLE_PREFIX_TELEGRAF   = "influxdb."
	VTABLE_PREFIX_PROMETHEUS = "prometheus."
)

type Counter struct {
	InCount                int64 `statsd:"in-count"`
	OutCount               int64 `statsd:"out-count"`
	ErrorCount             int64 `statsd:"err-count"`
	ErrMetrics             int64 `statsd:"err-metrics"`
	TimeSeries             int64 `statsd:"time-series"` // only for prometheus, count the number of TimeSeries (not Samples)
	DropUnsupportedMetrics int64 `statsd:"drop-unsupported-metrics"`
}

type Decoder struct {
	index            int
	msgType          datatype.MessageType
	platformData     *grpc.PlatformInfoTable
	inQueue          queue.QueueReader
	extMetricsWriter *dbwriter.ExtMetricsWriter
	debugEnabled     bool
	config           *config.Config

	// for prometheus, temporary buffers
	extMetricsBuffer []interface{} // store all Samples in a TimeSeries.
	tagNamesBuffer   []string      // store tag names in a time series
	tagValuesBuffer  []string      // store tag values in a time series

	// universal tag cache
	podNameToUniversalTag    map[string]*zerodoc.UniversalTag
	instanceIPToUniversalTag map[string]*zerodoc.UniversalTag
	vtapIDToUniversalTag     map[uint16]*zerodoc.UniversalTag
	platformDataVersion      uint64

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	extMetricsWriter *dbwriter.ExtMetricsWriter,
	config *config.Config,
) *Decoder {
	return &Decoder{
		index:                    index,
		msgType:                  msgType,
		platformData:             platformData,
		inQueue:                  inQueue,
		debugEnabled:             log.IsEnabledFor(logging.DEBUG),
		extMetricsWriter:         extMetricsWriter,
		config:                   config,
		counter:                  &Counter{},
		podNameToUniversalTag:    make(map[string]*zerodoc.UniversalTag),
		instanceIPToUniversalTag: make(map[string]*zerodoc.UniversalTag),
		vtapIDToUniversalTag:     make(map[uint16]*zerodoc.UniversalTag),
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	d.counter.DropUnsupportedMetrics = counter.DropUnsupportedMetrics
	return counter
}

func (d *Decoder) Run() {
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": d.msgType.String()})

	d.initMetricsTable()
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	prometheusMetric := &mpb.PrometheusMetric{}
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
			if d.msgType == datatype.MESSAGE_TYPE_TELEGRAF {
				d.handleTelegraf(recvBytes.VtapID, decoder)
			} else if d.msgType == datatype.MESSAGE_TYPE_PROMETHEUS {
				d.handlePrometheus(recvBytes.VtapID, decoder, prometheusMetric, extraLabels)
			} else if d.msgType == datatype.MESSAGE_TYPE_DFSTATS {
				d.handleDeepflowStats(recvBytes.VtapID, decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func (d *Decoder) initMetricsTable() {
	if d.msgType == datatype.MESSAGE_TYPE_TELEGRAF && d.extMetricsWriter != nil {
		// send empty metrics, trigger the creation of ext_metrics.metrics table
		m := dbwriter.AcquireExtMetrics()
		m.Timestamp = uint32(time.Now().Unix())
		d.extMetricsWriter.Write(m)
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
func prometheusMetricReset(m *mpb.PrometheusMetric) {
	m.Metrics = m.Metrics[:0]
	m.ExtraLabelNames = m.ExtraLabelNames[:0]
	m.ExtraLabelValues = m.ExtraLabelValues[:0]
}
func (d *Decoder) handlePrometheus(vtapID uint16, decoder *codec.SimpleDecoder, prometheusMetric *mpb.PrometheusMetric, extraLabels *[]prompb.Label) {
	for !decoder.IsEnd() {
		prometheusMetricReset(prometheusMetric)
		data := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("prometheus decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		if err := prometheusMetric.Unmarshal(data); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Warningf("prometheus metric parse failed, err msg: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		req, err := DecodeWriteRequest(prometheusMetric.Metrics)
		if err != nil {
			if d.counter.ErrorCount == 0 {
				log.Warningf("prometheus parse failed, err msg:%s", err)
			}
			d.counter.ErrorCount++
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
			req.Timeseries[i].Labels = append(req.Timeseries[i].Labels, *extraLabels...)
			d.sendPrometheus(vtapID, &req.Timeseries[i])
		}
	}
}

func (d *Decoder) sendPrometheus(vtapID uint16, ts *prompb.TimeSeries) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv promtheus timeseries: %v", d.index, vtapID, ts)
	}
	err := d.TimeSeriesToExtMetrics(vtapID, ts)
	if err != nil {
		if d.counter.ErrMetrics == 0 {
			log.Warning(err)
		}
		d.counter.ErrMetrics++
		return
	}
	d.extMetricsWriter.WriteBatch(d.extMetricsBuffer)
	d.counter.OutCount += int64(len(d.extMetricsBuffer))
	d.counter.TimeSeries++
}

func (d *Decoder) handleTelegraf(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("telegraf decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		points, err := models.ParsePoints(bytes)
		if err != nil {
			if d.counter.ErrorCount == 0 {
				log.Warningf("telegraf parse failed, err msg: %s", err)
			}
			d.counter.ErrorCount++
		}

		for _, point := range points {
			d.sendTelegraf(vtapID, point)
		}
	}
}

func (d *Decoder) sendTelegraf(vtapID uint16, point models.Point) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv telegraf point: %v", d.index, vtapID, point)
	}
	extMetrics, err := d.PointToExtMetrics(vtapID, point)
	if err != nil {
		if d.counter.ErrMetrics == 0 {
			log.Warning(err)
		}
		d.counter.ErrMetrics++
		return
	}
	d.extMetricsWriter.Write(extMetrics)
	d.counter.OutCount++
}

func (d *Decoder) handleDeepflowStats(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		pbStats := &pb.Stats{}
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("deepflow stats decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		if err := pbStats.Unmarshal(bytes); err != nil || pbStats.Name == "" {
			if d.counter.ErrorCount == 0 {
				log.Warningf("deepflow stats parse failed, err msg: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}

		if d.debugEnabled {
			log.Debugf("decoder %d vtap %d recv deepflow stats: %v", d.index, vtapID, pbStats)
		}
		d.extMetricsWriter.Write(StatsToExtMetrics(vtapID, pbStats))
		d.counter.OutCount++
	}
}

func StatsToExtMetrics(vtapID uint16, s *pb.Stats) *dbwriter.ExtMetrics {
	m := dbwriter.AcquireExtMetrics()
	m.Timestamp = uint32(s.Timestamp)
	m.UniversalTag.VTAPID = vtapID
	m.MsgType = datatype.MESSAGE_TYPE_DFSTATS
	m.VTableName = s.Name
	m.TagNames = s.TagNames
	m.TagValues = s.TagValues
	m.MetricsFloatNames = s.MetricsFloatNames
	m.MetricsFloatValues = s.MetricsFloatValues
	return m
}

func (d *Decoder) TimeSeriesToExtMetrics(vtapID uint16, ts *prompb.TimeSeries) error {
	if len(ts.Samples) == 0 {
		return nil
	}
	d.extMetricsBuffer = d.extMetricsBuffer[:0]
	d.tagNamesBuffer = d.tagNamesBuffer[:0]
	d.tagValuesBuffer = d.tagValuesBuffer[:0]

	metricNameLabel, podName, instance := "", "", ""
	for _, l := range ts.Labels {
		if l.Name == model.MetricNameLabel {
			metricNameLabel = l.Value
			continue
		}
		if l.Name == PROMETHEUS_POD {
			podName = l.Value
		} else if l.Name == PROMETHEUS_INSTANCE {
			instance = l.Value
		}
		d.tagNamesBuffer = append(d.tagNamesBuffer, l.Name)
		d.tagValuesBuffer = append(d.tagValuesBuffer, l.Value)
	}
	if metricNameLabel == "" {
		return fmt.Errorf("prometheum metric name label is null")
	}

	var universalTag *zerodoc.UniversalTag
	virtualTableName := VTABLE_PREFIX_PROMETHEUS + metricNameLabel
	for i, s := range ts.Samples {
		m := dbwriter.AcquireExtMetrics()

		m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
		m.MsgType = datatype.MESSAGE_TYPE_PROMETHEUS
		m.VTableName = virtualTableName

		m.TagNames = append(m.TagNames, d.tagNamesBuffer...)
		m.TagValues = append(m.TagValues, d.tagValuesBuffer...)

		v := float64(s.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			dbwriter.ReleaseExtMetrics(m)
			continue
		}
		m.MetricsFloatNames = append(m.MetricsFloatNames, metricNameLabel)
		m.MetricsFloatValues = append(m.MetricsFloatValues, v)

		if i == 0 {
			d.fillExtMetricsBase(m, vtapID, podName, instance, false)
			universalTag = &m.UniversalTag
		} else {
			// all samples share the same universal tag
			m.UniversalTag = *universalTag
		}
		d.extMetricsBuffer = append(d.extMetricsBuffer, m)
	}
	return nil
}

func (d *Decoder) fillExtMetricsBase(m *dbwriter.ExtMetrics, vtapID uint16, podName, instance string, fillWithVtapId bool) {
	var universalTag *zerodoc.UniversalTag
	var instanceIP string

	// fast path
	platformDataVersion := d.platformData.Version()
	if platformDataVersion != d.platformDataVersion {
		if d.platformDataVersion != 0 {
			log.Infof("platform data version in ext-metrics-decoder %s-#%d changed from %d to %d",
				d.msgType, d.index, d.platformDataVersion, platformDataVersion)
		}
		d.platformDataVersion = platformDataVersion
		d.podNameToUniversalTag = make(map[string]*zerodoc.UniversalTag)
		d.instanceIPToUniversalTag = make(map[string]*zerodoc.UniversalTag)
		d.vtapIDToUniversalTag = make(map[uint16]*zerodoc.UniversalTag)
	} else {
		if podName != "" {
			universalTag, _ = d.podNameToUniversalTag[podName]
		} else if instance != "" {
			instanceIP = getIPPartFromPrometheusInstanceString(instance)
			if instanceIP != "" {
				universalTag, _ = d.instanceIPToUniversalTag[instanceIP]
			}
		} else if fillWithVtapId {
			universalTag, _ = d.vtapIDToUniversalTag[vtapID]
		}
		if universalTag != nil {
			m.UniversalTag = *universalTag
			return
		}
	}

	// slow path
	d.fillExtMetricsBaseSlow(m, vtapID, podName, instanceIP, fillWithVtapId)

	// update fast path
	universalTag = &zerodoc.UniversalTag{} // Since the cache dictionary will be cleaned up by GC, no need to use a pool here.
	*universalTag = m.UniversalTag
	if podName != "" {
		d.podNameToUniversalTag[podName] = universalTag
	} else if instanceIP != "" {
		d.instanceIPToUniversalTag[instanceIP] = universalTag
	} else if fillWithVtapId {
		d.vtapIDToUniversalTag[vtapID] = universalTag
	}
}

func (d *Decoder) fillExtMetricsBaseSlow(m *dbwriter.ExtMetrics, vtapID uint16, podName, instanceIP string, fillWithVtapId bool) {
	t := &m.UniversalTag
	t.VTAPID = vtapID
	t.L3EpcID = datatype.EPC_FROM_INTERNET
	var ip net.IP
	if podName != "" {
		podInfo := d.platformData.QueryPodInfo(uint32(vtapID), podName)
		if podInfo != nil {
			t.PodClusterID = uint16(podInfo.PodClusterId)
			t.PodID = podInfo.PodId
			t.L3EpcID = podInfo.EpcId
			ip = net.ParseIP(podInfo.Ip)
		}
	} else if instanceIP != "" {
		t.L3EpcID = d.platformData.QueryVtapEpc0(uint32(vtapID))
		ip = net.ParseIP(instanceIP)
	} else if fillWithVtapId {
		t.L3EpcID = d.platformData.QueryVtapEpc0(uint32(vtapID))
		vtapInfo := d.platformData.QueryVtapInfo(uint32(vtapID))
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
		info = d.platformData.QueryIPV6Infos(t.L3EpcID, t.IP6)
	} else {
		info = d.platformData.QueryIPV4Infos(t.L3EpcID, t.IP)
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
			t.ServiceID = d.platformData.QueryService(t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, 0)
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

func (d *Decoder) PointToExtMetrics(vtapID uint16, point models.Point) (*dbwriter.ExtMetrics, error) {
	m := dbwriter.AcquireExtMetrics()
	m.Timestamp = uint32(point.Time().Unix())
	m.MsgType = datatype.MESSAGE_TYPE_TELEGRAF
	tableName := string(point.Name())
	m.VTableName = VTABLE_PREFIX_TELEGRAF + tableName
	podName := ""
	for _, tag := range point.Tags() {
		tagName := string(tag.Key)
		tagValue := string(tag.Value)
		m.TagNames = append(m.TagNames, tagName)
		m.TagValues = append(m.TagValues, tagValue)
		if tagName == TELEGRAF_POD {
			podName = tagValue
		}
	}
	d.fillExtMetricsBase(m, vtapID, podName, "", true)

	iter := point.FieldIterator()
	for iter.Next() {
		if len(iter.FieldKey()) == 0 {
			continue
		}
		switch iter.Type() {
		case models.Float:
			v, err := iter.FloatValue()
			if err != nil {
				dbwriter.ReleaseExtMetrics(m)
				return nil, fmt.Errorf("table %s unable to unmarshal field %s: %s", tableName, string(iter.FieldKey()), err)
			}
			m.MetricsFloatNames = append(m.MetricsFloatNames, string(iter.FieldKey()))
			m.MetricsFloatValues = append(m.MetricsFloatValues, v)
		case models.Integer:
			v, err := iter.IntegerValue()
			if err != nil {
				dbwriter.ReleaseExtMetrics(m)
				return nil, fmt.Errorf("table %s  unable to unmarshal field %s: %s", tableName, string(iter.FieldKey()), err)
			}
			m.MetricsFloatNames = append(m.MetricsFloatNames, string(iter.FieldKey()))
			m.MetricsFloatValues = append(m.MetricsFloatValues, float64(v))
		case models.Unsigned:
			v, err := iter.UnsignedValue()
			if err != nil {
				dbwriter.ReleaseExtMetrics(m)
				return nil, fmt.Errorf("table %s unable to unmarshal field %s: %s", tableName, string(iter.FieldKey()), err)
			}
			m.MetricsFloatNames = append(m.MetricsFloatNames, string(iter.FieldKey()))
			m.MetricsFloatValues = append(m.MetricsFloatValues, float64(v))
		case models.String, models.Boolean:
			if d.counter.DropUnsupportedMetrics&0xff == 0 {
				log.Warningf("table %s drop unsupported metrics name: %s type: %v. total drop %d", tableName, string(iter.FieldKey()), iter.Type(), d.counter.DropUnsupportedMetrics)
			}
			d.counter.DropUnsupportedMetrics++
		}
	}

	return m, nil
}
