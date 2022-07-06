package decoder

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/storage/remote"

	"github.com/metaflowys/metaflow/message/trident"
	"github.com/metaflowys/metaflow/server/ingester/common"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/config"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/dbwriter"
	"github.com/metaflowys/metaflow/server/libs/codec"
	"github.com/metaflowys/metaflow/server/libs/datatype"
	"github.com/metaflowys/metaflow/server/libs/grpc"
	"github.com/metaflowys/metaflow/server/libs/queue"
	"github.com/metaflowys/metaflow/server/libs/receiver"
	"github.com/metaflowys/metaflow/server/libs/stats"
	"github.com/metaflowys/metaflow/server/libs/utils"
	"github.com/metaflowys/metaflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("ext_metrics.decoder")

const (
	BUFFER_SIZE         = 1024
	TELEGRAF_POD        = "pod"
	PROMETHEUS_POD      = "pod_name"
	PROMETHEUS_INSTANCE = "instance"
)

type Counter struct {
	InCount                int64 `statsd:"in-count"`
	OutCount               int64 `statsd:"out-count"`
	ErrorCount             int64 `statsd:"err-count"`
	ErrMetrics             int64 `statsd:"err-metrics"`
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
		index:            index,
		msgType:          msgType,
		platformData:     platformData,
		inQueue:          inQueue,
		debugEnabled:     log.IsEnabledFor(logging.DEBUG),
		extMetricsWriter: extMetricsWriter,
		config:           config,
		counter:          &Counter{},
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
			if d.msgType == datatype.MESSAGE_TYPE_TELEGRAF {
				d.handleTelegraf(recvBytes.VtapID, decoder)
			} else if d.msgType == datatype.MESSAGE_TYPE_PROMETHEUS {
				d.handlePrometheus(recvBytes.VtapID, decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func (d *Decoder) handlePrometheus(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		data := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("prometheus decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		req, err := remote.DecodeWriteRequest(bytes.NewReader(data))
		if err != nil {
			if d.counter.ErrorCount == 0 {
				log.Warningf("prometheus parse failed, err msg:%s", err)
			}
			d.counter.ErrorCount++
		}

		for _, ts := range req.Timeseries {
			d.sendPrometheus(vtapID, &ts)
		}
	}
}

func (d *Decoder) sendPrometheus(vtapID uint16, ts *prompb.TimeSeries) {
	if d.debugEnabled {
		log.Debugf("decoder %d vtap %d recv promtheus timeseries: %v", d.index, vtapID, ts)
	}
	extMetrics, err := d.TimeSeriesToExtMetrics(vtapID, ts)
	if err != nil {
		if d.counter.ErrMetrics == 0 {
			log.Warning(err)
		}
		d.counter.ErrMetrics++
		return
	}
	for _, m := range extMetrics {
		d.extMetricsWriter.Write(m)
		d.counter.OutCount++
	}
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

// return the index of the character in 'str', which is the 'n' th same as 'c'
func findNthChar(str string, c byte, n int) int {
	if n <= 0 {
		return -1
	}
	for i := 0; i < len(str); i++ {
		if str[i] == c {
			n--
			if n == 0 {
				return i
			}
		}
	}
	return -1
}

func (d *Decoder) prometheusSplitMetricNameLabel(label string) (string, string) {
	index := findNthChar(label, '_', d.config.PrometheusSeparatePos)
	if index > 0 && index < len(label)-1 {
		return label[:index], label[index+1:]
	}

	return label, "value"
}

func (d *Decoder) TimeSeriesToExtMetrics(vtapID uint16, ts *prompb.TimeSeries) ([]*dbwriter.ExtMetrics, error) {
	ms := make([]*dbwriter.ExtMetrics, 0, len(ts.Samples))

	metricNameLabel, podName, instance := "", "", ""
	tagNames := make([]string, 0, len(ts.Labels))
	tagValues := make([]string, 0, len(ts.Labels))
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
		tagNames = append(tagNames, l.Name)
		tagValues = append(tagValues, l.Value)
	}
	if metricNameLabel == "" {
		return nil, fmt.Errorf("prometheum metric name label is null")
	}

	tableName, metricName := d.prometheusSplitMetricNameLabel(metricNameLabel)
	for _, s := range ts.Samples {
		m := dbwriter.AcquireExtMetrics()

		m.Timestamp = uint32(model.Time(s.Timestamp).Unix())
		m.TableName = tableName

		m.TagNames = tagNames
		m.TagValues = tagValues

		v := float64(s.Value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			dbwriter.ReleaseExtMetrics(m)
			continue
		}
		m.MetricsFloatNames = append(m.MetricsFloatNames, metricName)
		m.MetricsFloatValues = append(m.MetricsFloatValues, v)

		d.fillExtMetricsBase(m, vtapID, podName, instance)
		ms = append(ms, m)
	}
	return ms, nil
}

func (d *Decoder) fillExtMetricsBase(m *dbwriter.ExtMetrics, vtapID uint16, podName, instance string) {
	t := &m.Tag
	t.Code = zerodoc.AZID | zerodoc.HostID | zerodoc.IP | zerodoc.L3Device | zerodoc.L3EpcID | zerodoc.PodClusterID | zerodoc.PodGroupID | zerodoc.PodID | zerodoc.PodNodeID | zerodoc.PodNSID | zerodoc.RegionID | zerodoc.SubnetID | zerodoc.VTAPID | zerodoc.ServiceID | zerodoc.Resource
	t.VTAPID = vtapID
	t.L3EpcID = datatype.EPC_FROM_INTERNET
	var ip net.IP
	if podName != "" {
		podInfo := d.platformData.QueryPodInfo(uint32(vtapID), podName)
		if podInfo != nil {
			t.PodClusterID = uint16(podInfo.PodClusterId)
			t.PodID = podInfo.PodId
			t.L3EpcID = int16(podInfo.EpcId)
			ip = net.ParseIP(podInfo.Ip)
		}
	} else if instance != "" {
		t.L3EpcID = int16(d.platformData.QueryVtapEpc0(uint32(vtapID)))
		ip = parseIPFromInstance(instance)
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

		if t.L3DeviceType == zerodoc.DeviceType(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) ||
			t.PodID != 0 ||
			t.PodNodeID != 0 {
			if t.IsIPv6 == 1 {
				_, t.ServiceID = d.platformData.QueryIPv6IsKeyServiceAndID(t.L3EpcID, t.IP6, 0, 0)
			} else {
				_, t.ServiceID = d.platformData.QueryIsKeyServiceAndID(t.L3EpcID, t.IP, 0, 0)
			}
		}
		t.ResourceGl0ID, t.ResourceGl0Type = common.GetResourceGl0(t.PodID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
		t.ResourceGl1ID, t.ResourceGl1Type = common.GetResourceGl1(t.PodGroupID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
		t.ResourceGl2ID, t.ResourceGl2Type = common.GetResourceGl2(t.ServiceID, t.PodGroupID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), t.L3EpcID)
	}
}

// parse ip from "192.168.0.1:22" or "[2001:db8::68]:22"
func parseIPFromInstance(instance string) net.IP {
	var ipPart string
	index := strings.LastIndex(instance, ":")
	if index < 0 {
		ipPart = instance
	} else {
		ipPart = instance[:index]
	}
	if ipPart[0] == '[' && ipPart[len(ipPart)-1] == ']' {
		ipPart = ipPart[1 : len(ipPart)-1]
	}

	return net.ParseIP(ipPart)
}

func (d *Decoder) PointToExtMetrics(vtapID uint16, point models.Point) (*dbwriter.ExtMetrics, error) {
	m := dbwriter.AcquireExtMetrics()
	m.Timestamp = uint32(point.Time().Unix())
	tableName := string(point.Name())
	m.TableName = tableName
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
	d.fillExtMetricsBase(m, vtapID, podName, "")

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
			m.MetricsIntNames = append(m.MetricsIntNames, string(iter.FieldKey()))
			m.MetricsIntValues = append(m.MetricsIntValues, v)
		case models.Unsigned:
			v, err := iter.UnsignedValue()
			if err != nil {
				dbwriter.ReleaseExtMetrics(m)
				return nil, fmt.Errorf("table %s unable to unmarshal field %s: %s", tableName, string(iter.FieldKey()), err)
			}
			m.MetricsIntNames = append(m.MetricsIntNames, string(iter.FieldKey()))
			m.MetricsIntValues = append(m.MetricsIntValues, int64(v))
		case models.String, models.Boolean:
			if d.counter.DropUnsupportedMetrics&0xff == 0 {
				log.Warningf("table %s drop unsupported metrics name: %s type: %v. total drop %d", tableName, string(iter.FieldKey()), iter.Type(), d.counter.DropUnsupportedMetrics)
			}
			d.counter.DropUnsupportedMetrics++
		}
	}

	return m, nil
}
