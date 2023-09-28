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
	"net"
	"strconv"
	"time"

	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"

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
)

var log = logging.MustGetLogger("ext_metrics.decoder")

const (
	BUFFER_SIZE            = 128 // An ext_metrics message is usually very large, so use a smaller value than usual
	TELEGRAF_POD           = "pod_name"
	VTABLE_PREFIX_TELEGRAF = "influxdb."
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
		podNameToUniversalTag:    make(map[string]*zerodoc.UniversalTag),
		instanceIPToUniversalTag: make(map[string]*zerodoc.UniversalTag),
		vtapIDToUniversalTag:     make(map[uint16]*zerodoc.UniversalTag),
		counter:                  &Counter{},
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

func (d *Decoder) fillExtMetricsBase(m *dbwriter.ExtMetrics, vtapID uint16, podName string, fillWithVtapId bool) {
	var universalTag *zerodoc.UniversalTag

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
		} else if fillWithVtapId {
			universalTag, _ = d.vtapIDToUniversalTag[vtapID]
		}
		if universalTag != nil {
			m.UniversalTag = *universalTag
			return
		}
	}

	// slow path
	d.fillExtMetricsBaseSlow(m, vtapID, podName, fillWithVtapId)

	// update fast path
	universalTag = &zerodoc.UniversalTag{} // Since the cache dictionary will be cleaned up by GC, no need to use a pool here.
	*universalTag = m.UniversalTag
	if podName != "" {
		d.podNameToUniversalTag[podName] = universalTag
	} else if fillWithVtapId {
		d.vtapIDToUniversalTag[vtapID] = universalTag
	}
}

func (d *Decoder) fillExtMetricsBaseSlow(m *dbwriter.ExtMetrics, vtapID uint16, podName string, fillWithVtapId bool) {
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
		podGroupType := uint8(info.PodGroupType)
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
		t.AutoServiceID, t.AutoServiceType = common.GetAutoService(t.ServiceID, t.PodGroupID, t.GPID, t.PodNodeID, t.L3DeviceID, uint8(t.L3DeviceType), podGroupType, t.L3EpcID)
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
	d.fillExtMetricsBase(m, vtapID, podName, true)

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
