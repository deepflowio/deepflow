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
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	json "github.com/bytedance/sonic"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/app_log/config"
	"github.com/deepflowio/deepflow/server/ingester/app_log/dbwriter"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("app_log.decoder")

const (
	BUFFER_SIZE = 1024
	SEPARATOR   = ", "
)

const (
	SEVERITY_FATAL uint8 = 2 + iota // value as log/syslog.LOG_CRIT
	SEVERITY_ERROR                  // value as log/syslog.LOG_ERR
	SEVERITY_WARN                   // value as log/syslog.LOG_WARN
	SEVERITY_INFO                   // value as log/syslog.LOG_INFO
	SEVERITY_DEBUG                  // value as log/syslog.LOG_DEBUG
	SEVERITY_TRACE
	SEVERITY_UNKNOWN
)

var SeverityMap = map[string]uint8{
	"FATAL": SEVERITY_FATAL,
	"ERROR": SEVERITY_ERROR,
	"WARN":  SEVERITY_WARN,
	"INFO":  SEVERITY_INFO,
	"DEBUG": SEVERITY_DEBUG,
	"TRACE": SEVERITY_TRACE,

	"FATAL2": SEVERITY_FATAL,
	"ERROR2": SEVERITY_ERROR,
	"WARN2":  SEVERITY_WARN,
	"INFO2":  SEVERITY_INFO,
	"DEBUG2": SEVERITY_DEBUG,
	"TRACE2": SEVERITY_TRACE,

	"FATAL3": SEVERITY_FATAL,
	"ERROR3": SEVERITY_ERROR,
	"WARN3":  SEVERITY_WARN,
	"INFO3":  SEVERITY_INFO,
	"DEBUG3": SEVERITY_DEBUG,
	"TRACE3": SEVERITY_TRACE,

	"FATAL4": SEVERITY_FATAL,
	"ERROR4": SEVERITY_ERROR,
	"WARN4":  SEVERITY_WARN,
	"INFO4":  SEVERITY_INFO,
	"DEBUG4": SEVERITY_DEBUG,
	"TRACE4": SEVERITY_TRACE,

	"CRITICAL": SEVERITY_FATAL,
	"WARNING":  SEVERITY_WARN,
	"ERRO":     SEVERITY_ERROR,
	"DEBU":     SEVERITY_DEBUG,
	"FATA":     SEVERITY_FATAL,
	"CRIT":     SEVERITY_FATAL,
}

func StringToSeverity(str string) uint8 {
	upperStr := strings.ToUpper(str)
	if severity, ok := SeverityMap[upperStr]; ok {
		return severity
	}
	return SEVERITY_UNKNOWN
}

type Counter struct {
	InCount    int64 `statsd:"in-count"`
	OutCount   int64 `statsd:"out-count"`
	ErrorCount int64 `statsd:"err-count"`
}

type Decoder struct {
	index             int
	msgType           datatype.MessageType
	platformData      *grpc.PlatformInfoTable
	inQueue           queue.QueueReader
	logWriter         *dbwriter.AppLogWriter
	debugEnabled      bool
	config            *config.Config
	appLogEntrysCache []AppLogEntry
	orgId, teamId     uint16

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int,
	msgType datatype.MessageType,
	inQueue queue.QueueReader,
	logWriter *dbwriter.AppLogWriter,
	platformData *grpc.PlatformInfoTable,
	config *config.Config,
) *Decoder {
	return &Decoder{
		index:             index,
		msgType:           msgType,
		platformData:      platformData,
		inQueue:           inQueue,
		debugEnabled:      log.IsEnabledFor(logging.DEBUG),
		logWriter:         logWriter,
		appLogEntrysCache: make([]AppLogEntry, 0),
		config:            config,
		counter:           &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	log.Infof("application log (%s-%d) decoder run", d.msgType.String(), d.index)
	ingestercommon.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
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
				log.Warning("get application log decode queue data type wrong")
				continue
			}
			decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
			d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
			switch d.msgType {
			case datatype.MESSAGE_TYPE_APPLICATION_LOG:
				d.handleAppLog(recvBytes.VtapID, decoder)
			case datatype.MESSAGE_TYPE_SYSLOG, datatype.MESSAGE_TYPE_AGENT_LOG:
				d.handleAgentLog(recvBytes.VtapID, decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
	}
}

func (d *Decoder) handleAgentLog(agentId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("syslog decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}

		if err := d.WriteAgentLog(agentId, bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("syslog parse failed: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
	}
}

func (d *Decoder) WriteAgentLog(agentId uint16, bs []byte) error {
	s := dbwriter.AcquireApplicationLogStore()

	log.Debugf("recv agentId: %d, syslog %s", agentId, bs)
	// example log
	// 2024-04-30T10:26:47.038297752+08:00 mars-1-V3 mars-1[5874]: [ERROR] src/sender/uniform_sender.rs:431 2-protolog-to-collector-sender sender tcp connection to 10.233.100.189:20033 failed
	columns := bytes.SplitN(bs, []byte{' '}, 6)
	if len(columns) != 6 {
		return fmt.Errorf("log parts is %d", len(columns))
	}
	datetime, err := time.Parse(time.RFC3339, string(columns[0]))
	if err != nil {
		return err
	}

	s.Type = dbwriter.LOG_TYPE_AGENT
	s.Time = uint32(datetime.Unix())
	s.Timestamp = int64(datetime.UnixMicro())
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.AgentID = agentId

	host := string(columns[1])
	s.AttributeNames = append(s.AttributeNames, "host")
	s.AttributeValues = append(s.AttributeValues, host)
	s.AppService = host
	s.OrgId, s.TeamID = d.orgId, d.teamId

	// If it is an old version of the Agent, or when the Agent is just started, the value of agentId will be 0.
	if agentId != 0 {
		var info *grpc.Info
		s.L3EpcID = d.platformData.QueryVtapEpc0(s.OrgId, agentId)
		// if platformInfo cannot be obtained from PodId, finally fill with Vtap's platformInfo
		vtapInfo := d.platformData.QueryVtapInfo(s.OrgId, agentId)
		if vtapInfo != nil {
			ip := net.ParseIP(vtapInfo.Ip)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					s.IsIPv4 = true
					s.IP4 = utils.IpToUint32(ip4)
					info = d.platformData.QueryIPV4Infos(s.OrgId, s.L3EpcID, s.IP4)
				} else {
					s.IsIPv4 = false
					s.IP6 = ip
					info = d.platformData.QueryIPV6Infos(s.OrgId, s.L3EpcID, s.IP6)
				}
			}
		}

		podGroupType := uint8(0)
		if info != nil {
			s.RegionID = uint16(info.RegionID)
			s.AZID = uint16(info.AZID)
			s.L3EpcID = info.EpcID
			s.HostID = uint16(info.HostID)
			s.PodID = info.PodID
			s.PodNodeID = info.PodNodeID
			s.PodNSID = uint16(info.PodNSID)
			s.PodClusterID = uint16(info.PodClusterID)
			s.PodGroupID = info.PodGroupID
			podGroupType = info.PodGroupType
			s.L3DeviceType = uint8(info.DeviceType)
			s.L3DeviceID = info.DeviceID
			s.SubnetID = uint16(info.SubnetID)
			// if it is just Pod Node, there is no need to match the service
			if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
				s.ServiceID = d.platformData.QueryPodService(s.OrgId,
					s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
			}
		} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.OrgId, s.L3EpcID); baseInfo != nil {
			s.RegionID = uint16(baseInfo.RegionID)
		}

		s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, 0, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), s.L3EpcID)
		customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType))
		s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(customServiceID, s.ServiceID, s.PodGroupID, 0, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), podGroupType, s.L3EpcID)
	}

	severityText := ""
	switch string(columns[3]) {
	case "[INFO]":
		severityText = "INFO"
	case "[WARN]":
		severityText = "WARN"
	case "[ERRO]", "[ERROR]":
		severityText = "ERROR"
	case "[DEBU]", "[DEBUG]":
		severityText = "DEBUG"
	default:
		return fmt.Errorf("ignored log level: %s", string(columns[3]))
	}
	s.SeverityNumber = StringToSeverity(severityText)
	s.Body = string(columns[5])

	s.AttributeNames = append(s.AttributeNames, "module")
	s.AttributeValues = append(s.AttributeValues, string(columns[4]))

	d.logWriter.Write(s)
	return nil
}

func (d *Decoder) WriteAppLog(agentId uint16, l *AppLogEntry) error {
	s := dbwriter.AcquireApplicationLogStore()
	timeObj, err := time.Parse(time.RFC3339, l.Timestamp)
	if err != nil {
		return fmt.Errorf("%s error parsing timestamp: %s", l.Timestamp, err)
	}

	if l.Message == "" {
		return fmt.Errorf("application log body is empty. agent id: %d, log: %v", agentId, l)
	}

	s.Body = strings.Clone(l.Message)
	s.Type = dbwriter.StringToLogType(l.LogType)
	s.UserID = uint32(l.UserID)
	s.TraceID = l.TraceID
	s.SpanID = l.SpanID

	s.Time = uint32(timeObj.Unix())
	s.Timestamp = timeObj.UnixMicro()
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())

	s.AgentID = agentId

	switch s.Type {
	case dbwriter.LOG_TYPE_SYSTEM:
		s.OrgId, s.TeamID = ckdb.DEFAULT_ORG_ID, ckdb.INVALID_TEAM_ID
	case dbwriter.LOG_TYPE_AUDIT:
		s.OrgId, s.TeamID = uint16(l.OrgID), ckdb.INVALID_TEAM_ID
	default:
		s.OrgId, s.TeamID = d.orgId, d.teamId
	}

	s.L3EpcID = d.platformData.QueryVtapEpc0(s.OrgId, agentId)

	if l.Json != nil {
		switch v := l.Json.(type) {
		case map[string]interface{}:
			var strValue string
			for key, value := range v {
				if s, ok := value.(string); ok {
					strValue = strings.Clone(s)
				} else {
					strValue = fmt.Sprintf("%v", value)
				}
				s.AttributeNames = append(s.AttributeNames, strings.Clone(key))
				s.AttributeValues = append(s.AttributeValues, strValue)
			}
		default:
			if d.counter.ErrorCount == 0 {
				log.Warningf("parse application log json filed failed. %v", l.Json)
			}
			d.counter.ErrorCount++
		}
	}

	s.SeverityNumber = StringToSeverity(l.Level)
	s.AppService = strings.Clone(l.AppService)

	if l.Kubernetes.PodIp != "" {
		s.AttributeNames = append(s.AttributeNames, "pod_ip", "pod_name")
		s.AttributeValues = append(s.AttributeValues, strings.Clone(l.Kubernetes.PodIp), strings.Clone(l.Kubernetes.PodName))
	}

	podName := l.Kubernetes.PodName
	var ip net.IP
	if l.Kubernetes.PodIp != "" {
		ip = net.ParseIP(l.Kubernetes.PodIp)
	}
	if podName != "" {
		podInfo := d.platformData.QueryPodInfo(s.OrgId, agentId, podName)
		if podInfo != nil {
			s.PodClusterID = uint16(podInfo.PodClusterId)
			s.PodID = podInfo.PodId
			s.L3EpcID = podInfo.EpcId
			if ip == nil {
				ip = net.ParseIP(podInfo.Ip)
				// maybe Pod is hostnetwork mode or can't get pod IP, then get pod node IP instead
				if ip == nil {
					ip = net.ParseIP(podInfo.PodNodeIp)
				}
			}
		}
	}

	if ip == nil {
		// if platformInfo cannot be obtained from PodId, finally fill with Vtap's platformInfo
		vtapInfo := d.platformData.QueryVtapInfo(s.OrgId, agentId)
		if vtapInfo != nil {
			ip = net.ParseIP(vtapInfo.Ip)
		}
	}

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			s.IsIPv4 = true
			s.IP4 = utils.IpToUint32(ip4)
		} else {
			s.IsIPv4 = false
			s.IP6 = ip
		}
	}

	var info *grpc.Info
	if s.PodID != 0 {
		info = d.platformData.QueryPodIdInfo(s.OrgId, s.PodID)
	} else {
		if s.IsIPv4 && ip != nil {
			info = d.platformData.QueryIPV4Infos(s.OrgId, s.L3EpcID, s.IP4)
		} else {
			info = d.platformData.QueryIPV6Infos(s.OrgId, s.L3EpcID, s.IP6)
		}
	}

	podGroupType := uint8(0)
	if info != nil {
		s.RegionID = uint16(info.RegionID)
		s.AZID = uint16(info.AZID)
		s.L3EpcID = info.EpcID
		s.HostID = uint16(info.HostID)
		if s.PodID == 0 {
			s.PodID = info.PodID
		}
		s.PodNodeID = info.PodNodeID
		s.PodNSID = uint16(info.PodNSID)
		s.PodClusterID = uint16(info.PodClusterID)
		s.PodGroupID = info.PodGroupID
		podGroupType = info.PodGroupType
		s.L3DeviceType = uint8(info.DeviceType)
		s.L3DeviceID = info.DeviceID
		s.SubnetID = uint16(info.SubnetID)
		s.IsIPv4 = info.IsIPv4
		s.IP4 = info.IP4
		s.IP6 = info.IP6
		// if it is just Pod Node, there is no need to match the service
		if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
			s.ServiceID = d.platformData.QueryPodService(s.OrgId,
				s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
		}
	} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.OrgId, s.L3EpcID); baseInfo != nil {
		s.RegionID = uint16(baseInfo.RegionID)
	}

	s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, 0, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), s.L3EpcID)
	customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType))
	s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(customServiceID, s.ServiceID, s.PodGroupID, 0, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), podGroupType, s.L3EpcID)

	d.logWriter.Write(s)
	return nil
}

type AppLogEntry struct {
	LogType    string `json:"_df_log_type"`
	UserID     int    `json:"user_id"`
	OrgID      int    `json:"org_id"`
	Kubernetes struct {
		PodName string `json:"pod_name"`
		PodIp   string `json:"pod_ip"`
	} `json:"kubernetes"`
	Message    string      `json:"message"`
	Json       interface{} `json:"json"`
	Level      string      `json:"level"`
	Timestamp  string      `json:"timestamp"`
	AppService string      `json:"app_service"`
	TraceID    string      `json:"trace_id"`
	SpanID     string      `json:"span_id"`
}

func (d *Decoder) handleAppLog(agentId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("application log decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		d.counter.OutCount++

		log.Debugf("recv agent Id: %d, applog: %s", agentId, bytes)
		d.appLogEntrysCache = d.appLogEntrysCache[:0]
		err := json.UnmarshalString(utils.String(bytes), &d.appLogEntrysCache)
		if err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("application log (%s) json decode (%d) failed: %s", utils.String(bytes), len(d.appLogEntrysCache), err)
			}
			d.counter.ErrorCount++
			// since it is batch parsing, even if it fails in the end,
			//   but some data may have been successfully parsed and returned in 'd.appLogEntrysCache',
			//   so it needs to continue and should not be returned.
		}
		for i, appLogEntry := range d.appLogEntrysCache {
			if err := d.WriteAppLog(agentId, &appLogEntry); err != nil {
				if d.counter.ErrorCount == 0 {
					log.Warningf("application log decode failed: %s", err)
				}
				d.counter.ErrorCount++
			}
			// need to reset, otherwise json parsing will use the last value as the default value
			d.appLogEntrysCache[i] = AppLogEntry{}
		}
	}
}
