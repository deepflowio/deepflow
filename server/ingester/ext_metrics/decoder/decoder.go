package decoder

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/influxdata/influxdb/models"
	"server/libs/zerodoc"

	logging "github.com/op/go-logging"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/storage/remote"
	"server/libs/codec"
	"server/libs/datatype"
	"server/libs/grpc"
	"server/libs/queue"
	"server/libs/receiver"
	"server/libs/stats"
	"server/libs/utils"
	"server/ingester/ext_metrics/dbwriter"
)

var log = logging.MustGetLogger("ext_metrics.decoder")

const (
	BUFFER_SIZE = 1024
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

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	extMetricsWriter *dbwriter.ExtMetricsWriter,
) *Decoder {
	return &Decoder{
		index:            index,
		msgType:          msgType,
		platformData:     platformData,
		inQueue:          inQueue,
		debugEnabled:     log.IsEnabledFor(logging.DEBUG),
		extMetricsWriter: extMetricsWriter,
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
	stats.RegisterCountable("decoder", d, stats.OptionStatTags{
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

var podTags = []string{"pod", "pod_name"}

func isPod(name string) bool {
	for _, v := range podTags {
		if name == v {
			return true
		}
	}
	return false
}

func (d *Decoder) TimeSeriesToExtMetrics(vtapID uint16, ts *prompb.TimeSeries) ([]*dbwriter.ExtMetrics, error) {
	ms := make([]*dbwriter.ExtMetrics, 0, len(ts.Samples))

	tableName, podName := "", ""
	tagNames := make([]string, 0, len(ts.Labels))
	tagValues := make([]string, 0, len(ts.Labels))
	for _, l := range ts.Labels {
		if l.Name == model.MetricNameLabel {
			tableName = l.Value
			continue
		}
		if isPod(l.Name) {
			podName = l.Value
		}
		tagNames = append(tagNames, l.Name)
		tagValues = append(tagValues, l.Value)
	}
	if tableName == "" {
		return nil, fmt.Errorf("table name is null")
	}

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
		m.MetricsFloatNames = append(m.MetricsFloatNames, "value")
		m.MetricsFloatValues = append(m.MetricsFloatValues, v)

		d.fillExtMetricsBase(m, vtapID, podName)
		ms = append(ms, m)
	}
	return ms, nil
}

func (d *Decoder) fillExtMetricsBase(m *dbwriter.ExtMetrics, vtapID uint16, podName string) {
	m.Tag.Code = zerodoc.AZID | zerodoc.HostID | zerodoc.IP | zerodoc.L3Device | zerodoc.L3EpcID | zerodoc.PodClusterID | zerodoc.PodGroupID | zerodoc.PodID | zerodoc.PodNodeID | zerodoc.PodNSID | zerodoc.RegionID | zerodoc.SubnetID | zerodoc.VTAPID
	m.Tag.VTAPID = vtapID
	m.Tag.L3EpcID = datatype.EPC_FROM_INTERNET
	if podName != "" {
		podInfo := d.platformData.QueryPodInfo(uint32(vtapID), podName)
		if podInfo != nil {
			m.Tag.PodClusterID = uint16(podInfo.PodClusterId)
			m.Tag.PodID = podInfo.PodId
			m.Tag.L3EpcID = int16(podInfo.EpcId)
			ip := net.ParseIP(podInfo.Ip)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					m.Tag.IsIPv6 = 0
					m.Tag.IP = utils.IpToUint32(ip4)
				} else {
					m.Tag.IsIPv6 = 1
					m.Tag.IP6 = ip
				}
			}
			var info *grpc.Info
			if m.Tag.IsIPv6 == 1 {
				info = d.platformData.QueryIPV6Infos(m.Tag.L3EpcID, m.Tag.IP6)
			} else {
				info = d.platformData.QueryIPV4Infos(m.Tag.L3EpcID, m.Tag.IP)
			}
			if info != nil {
				m.Tag.RegionID = uint16(info.RegionID)
				m.Tag.AZID = uint16(info.AZID)
				m.Tag.HostID = uint16(info.HostID)
				m.Tag.PodGroupID = info.PodGroupID
				m.Tag.PodNSID = uint16(info.PodNSID)
				m.Tag.PodNodeID = info.PodNodeID
				m.Tag.SubnetID = uint16(info.SubnetID)
				m.Tag.L3DeviceID = info.DeviceID
				m.Tag.L3DeviceType = zerodoc.DeviceType(info.DeviceType)
			}
		}
	}
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
		if isPod(tagName) {
			podName = tagValue
		}
	}
	d.fillExtMetricsBase(m, vtapID, podName)

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
