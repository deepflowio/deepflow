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
	"net"
	"strconv"

	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	"github.com/deepflowio/deepflow/server/libs/utils"
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
	index             int
	msgType           datatype.MessageType
	platformData      *grpc.PlatformInfoTable
	inQueue           queue.QueueReader
	extMetricsWriters [dbwriter.MAX_DB_ID]*dbwriter.ExtMetricsWriter
	debugEnabled      bool
	config            *config.Config

	// universal tag cache
	podNameToUniversalTag    [grpc.MAX_ORG_COUNT]map[string]*flow_metrics.UniversalTag
	instanceIPToUniversalTag [grpc.MAX_ORG_COUNT]map[string]*flow_metrics.UniversalTag
	vtapIDToUniversalTag     [grpc.MAX_ORG_COUNT]map[uint16]*flow_metrics.UniversalTag
	platformDataVersion      [grpc.MAX_ORG_COUNT]uint64

	orgId, teamId uint16

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	extMetricsWriters [dbwriter.MAX_DB_ID]*dbwriter.ExtMetricsWriter,
	config *config.Config,
) *Decoder {
	d := &Decoder{
		index:             index,
		msgType:           msgType,
		platformData:      platformData,
		inQueue:           inQueue,
		debugEnabled:      log.IsEnabledFor(logging.DEBUG),
		extMetricsWriters: extMetricsWriters,
		config:            config,
		counter:           &Counter{},
	}
	for i := 0; i < grpc.MAX_ORG_COUNT; i++ {
		d.podNameToUniversalTag[i] = make(map[string]*flow_metrics.UniversalTag)
		d.instanceIPToUniversalTag[i] = make(map[string]*flow_metrics.UniversalTag)
		d.vtapIDToUniversalTag[i] = make(map[uint16]*flow_metrics.UniversalTag)
	}
	return d
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
			d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
			if d.msgType == datatype.MESSAGE_TYPE_TELEGRAF {
				d.handleTelegraf(recvBytes.VtapID, decoder)
			} else if d.msgType == datatype.MESSAGE_TYPE_DFSTATS || d.msgType == datatype.MESSAGE_TYPE_SERVER_DFSTATS {
				d.handleDeepflowStats(recvBytes.VtapID, decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
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
	if err != nil || !extMetrics.IsValid() {
		if d.counter.ErrMetrics == 0 {
			log.Warning(err)
		}
		d.counter.ErrMetrics++
		return
	}
	d.extMetricsWriters[int(dbwriter.EXT_METRICS_DB_ID)].Write(extMetrics)
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
		metrics, dbId := d.StatsToExtMetrics(vtapID, pbStats)
		if !metrics.IsValid() {
			if d.counter.ErrMetrics == 0 {
				log.Warningf("ext metrics is invalid. %+v", metrics)
			}
			d.counter.ErrMetrics++
			continue
		}
		d.extMetricsWriters[dbId].Write(metrics)
		d.counter.OutCount++
	}
}

func (d *Decoder) StatsToExtMetrics(vtapID uint16, s *pb.Stats) (*dbwriter.ExtMetrics, dbwriter.WriterDBID) {
	m := dbwriter.AcquireExtMetrics()
	m.Timestamp = uint32(s.Timestamp)
	m.UniversalTag.VTAPID = vtapID
	m.MsgType = d.msgType
	m.VTableName = s.Name
	m.TagNames = s.TagNames
	m.TagValues = s.TagValues
	m.MetricsFloatNames = s.MetricsFloatNames
	m.MetricsFloatValues = s.MetricsFloatValues
	m.RawOrgId = uint16(s.OrgId)
	var writerDBID dbwriter.WriterDBID
	// if OrgId is set, the set OrgId will be used first.
	if s.OrgId != 0 {
		m.OrgId, m.TeamID = uint16(s.OrgId), uint16(s.TeamId)
		writerDBID = dbwriter.DEEPFLOW_TENANT_DB_ID
	} else { // OrgId not set
		// from deepflow_server, OrgId set default
		if m.MsgType == datatype.MESSAGE_TYPE_SERVER_DFSTATS {
			m.OrgId, m.TeamID = ckdb.DEFAULT_ORG_ID, ckdb.DEFAULT_TEAM_ID
			writerDBID = dbwriter.DEEPFLOW_ADMIN_DB_ID
		} else { // from deepflow_agent, OrgId Get from header first, then from vtapID
			m.OrgId, m.TeamID = d.orgId, d.teamId
			writerDBID = dbwriter.DEEPFLOW_TENANT_DB_ID
		}
	}
	return m, writerDBID
}

func (d *Decoder) fillExtMetricsBase(m *dbwriter.ExtMetrics, vtapID uint16, podName string, fillWithVtapId bool) {
	var universalTag *flow_metrics.UniversalTag

	// fast path
	platformDataVersion := d.platformData.Version(m.OrgId)
	if platformDataVersion != d.platformDataVersion[m.OrgId] {
		if d.platformDataVersion[m.OrgId] != 0 {
			log.Infof("platform data version in ext-metrics-decoder %s-#%d changed from %d to %d",
				d.msgType, d.index, d.platformDataVersion, platformDataVersion)
		}
		d.platformDataVersion[m.OrgId] = platformDataVersion
		d.podNameToUniversalTag[m.OrgId] = make(map[string]*flow_metrics.UniversalTag)
		d.instanceIPToUniversalTag[m.OrgId] = make(map[string]*flow_metrics.UniversalTag)
		d.vtapIDToUniversalTag[m.OrgId] = make(map[uint16]*flow_metrics.UniversalTag)
	} else {
		if podName != "" {
			universalTag, _ = d.podNameToUniversalTag[m.OrgId][podName]
		} else if fillWithVtapId {
			universalTag, _ = d.vtapIDToUniversalTag[m.OrgId][vtapID]
		}
		if universalTag != nil {
			m.UniversalTag = *universalTag
			return
		}
	}

	// slow path
	d.fillExtMetricsBaseSlow(m, vtapID, podName, fillWithVtapId)

	// update fast path
	universalTag = &flow_metrics.UniversalTag{} // Since the cache dictionary will be cleaned up by GC, no need to use a pool here.
	*universalTag = m.UniversalTag
	if podName != "" {
		d.podNameToUniversalTag[m.OrgId][podName] = universalTag
	} else if fillWithVtapId {
		d.vtapIDToUniversalTag[m.OrgId][vtapID] = universalTag
	}
}

func (d *Decoder) fillExtMetricsBaseSlow(m *dbwriter.ExtMetrics, vtapID uint16, podName string, fillWithVtapId bool) {
	t := &m.UniversalTag
	t.VTAPID = vtapID
	t.L3EpcID = datatype.EPC_FROM_INTERNET
	var ip net.IP
	if podName != "" {
		podInfo := d.platformData.QueryPodInfo(m.OrgId, vtapID, podName)
		if podInfo != nil {
			t.PodClusterID = uint16(podInfo.PodClusterId)
			t.PodID = podInfo.PodId
			t.L3EpcID = podInfo.EpcId
			ip = net.ParseIP(podInfo.Ip)
		}
	} else if fillWithVtapId {
		t.L3EpcID = d.platformData.QueryVtapEpc0(m.OrgId, vtapID)
		vtapInfo := d.platformData.QueryVtapInfo(m.OrgId, vtapID)
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
		info = d.platformData.QueryIPV6Infos(m.OrgId, t.L3EpcID, t.IP6)
	} else {
		info = d.platformData.QueryIPV4Infos(m.OrgId, t.L3EpcID, t.IP)
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
		t.L3DeviceType = flow_metrics.DeviceType(info.DeviceType)
		if t.PodClusterID == 0 {
			t.PodClusterID = uint16(info.PodClusterID)
		}
		if t.PodID == 0 {
			t.PodID = info.PodID
		}

		if common.IsPodServiceIP(t.L3DeviceType, t.PodID, t.PodNodeID) {
			t.ServiceID = d.platformData.QueryPodService(m.OrgId, t.PodID, t.PodNodeID, uint32(t.PodClusterID), t.PodGroupID, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, 0)
		}
		t.AutoInstanceID, t.AutoInstanceType = common.GetAutoInstance(t.PodID, t.GPID, t.PodNodeID, t.L3DeviceID, uint32(t.SubnetID), uint8(t.L3DeviceType), t.L3EpcID)
		customServiceID := d.platformData.QueryCustomService(m.OrgId, t.L3EpcID, t.IsIPv6 == 1, t.IP, t.IP6, 0, t.ServiceID, t.PodGroupID, t.L3DeviceID, t.PodID, uint8(t.L3DeviceType))
		t.AutoServiceID, t.AutoServiceType = common.GetAutoService(customServiceID, t.ServiceID, t.PodGroupID, t.GPID, uint32(t.PodClusterID), t.L3DeviceID, uint32(t.SubnetID), uint8(t.L3DeviceType), podGroupType, t.L3EpcID)
	}
}

func (d *Decoder) PointToExtMetrics(vtapID uint16, point models.Point) (*dbwriter.ExtMetrics, error) {
	m := dbwriter.AcquireExtMetrics()
	m.Timestamp = uint32(point.Time().Unix())
	m.MsgType = datatype.MESSAGE_TYPE_TELEGRAF
	tableName := string(point.Name())
	m.VTableName = VTABLE_PREFIX_TELEGRAF + tableName
	m.OrgId, m.TeamID = d.orgId, d.teamId
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
