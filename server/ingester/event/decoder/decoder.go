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
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/alert_event"
	"github.com/deepflowio/deepflow/message/trident"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	exporterscommon "github.com/deepflowio/deepflow/server/ingester/exporters/common"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("event.decoder")

const (
	BUFFER_SIZE = 1024
	SEPARATOR   = ", "
)

type Counter struct {
	InCount    int64 `statsd:"in-count"`
	OutCount   int64 `statsd:"out-count"`
	ErrorCount int64 `statsd:"err-count"`
}

type AiAgentRootPidCache struct {
	mu           sync.RWMutex
	rootPidByKey map[uint64]uint32
}

func NewAiAgentRootPidCache() *AiAgentRootPidCache {
	return &AiAgentRootPidCache{
		rootPidByKey: make(map[uint64]uint32),
	}
}

func aiAgentRootPidKey(orgId, vtapId uint16, pid uint32) uint64 {
	return uint64(orgId)<<48 | uint64(vtapId)<<32 | uint64(pid)
}

func (c *AiAgentRootPidCache) Get(orgId, vtapId uint16, pid uint32) (uint32, bool) {
	if c == nil || pid == 0 {
		return 0, false
	}
	key := aiAgentRootPidKey(orgId, vtapId, pid)
	c.mu.RLock()
	defer c.mu.RUnlock()
	rootPid, ok := c.rootPidByKey[key]
	return rootPid, ok
}

func (c *AiAgentRootPidCache) Set(orgId, vtapId uint16, pid, rootPid uint32) {
	if c == nil || pid == 0 {
		return
	}
	key := aiAgentRootPidKey(orgId, vtapId, pid)
	c.mu.Lock()
	c.rootPidByKey[key] = rootPid
	c.mu.Unlock()
}

func (c *AiAgentRootPidCache) Delete(orgId, vtapId uint16, pid uint32) {
	if c == nil || pid == 0 {
		return
	}
	key := aiAgentRootPidKey(orgId, vtapId, pid)
	c.mu.Lock()
	delete(c.rootPidByKey, key)
	c.mu.Unlock()
}

func (c *AiAgentRootPidCache) ResolveRootPid(orgId, vtapId uint16, pid, parentPid uint32) uint32 {
	if c == nil || pid == 0 {
		return 0
	}
	if rootPid, ok := c.Get(orgId, vtapId, pid); ok && rootPid != 0 {
		return rootPid
	}
	if parentPid != 0 && parentPid != pid {
		if rootPid, ok := c.Get(orgId, vtapId, parentPid); ok && rootPid != 0 {
			c.Set(orgId, vtapId, pid, rootPid)
			return rootPid
		}
		c.Set(orgId, vtapId, pid, parentPid)
		return parentPid
	}
	c.Set(orgId, vtapId, pid, pid)
	return pid
}

type Decoder struct {
	index               int
	eventType           common.EventType
	platformData        *grpc.PlatformInfoTable
	inQueue             queue.QueueReader
	eventWriter         *dbwriter.EventWriter
	procEventWriters    *ProcEventWriters
	fileAggReducer      *FileAggReducer
	fileMgmtReducer     *FileMgmtReducer
	exporters           *exporters.Exporters
	debugEnabled        bool
	config              *config.Config
	aiAgentRootPidCache *AiAgentRootPidCache

	orgId, teamId uint16

	counter *Counter
	utils.Closable
}

type ProcEventWriters struct {
	FileWriter     *dbwriter.EventWriter
	FileAggWriter  *dbwriter.EventWriter
	FileMgmtWriter *dbwriter.EventWriter
	ProcPermWriter *dbwriter.EventWriter
	ProcOpsWriter  *dbwriter.EventWriter
}

func NewDecoder(
	index int,
	eventType common.EventType,
	inQueue queue.QueueReader,
	eventWriter *dbwriter.EventWriter,
	procEventWriters *ProcEventWriters,
	platformData *grpc.PlatformInfoTable,
	exporters *exporters.Exporters,
	config *config.Config,
	aiAgentRootPidCache *AiAgentRootPidCache,
) *Decoder {
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	return &Decoder{
		index:               index,
		eventType:           eventType,
		platformData:        platformData,
		inQueue:             inQueue,
		debugEnabled:        log.IsEnabledFor(logging.DEBUG),
		eventWriter:         eventWriter,
		procEventWriters:    procEventWriters,
		fileAggReducer:      NewFileAggReducer(),
		fileMgmtReducer:     NewFileMgmtReducer(),
		exporters:           exporters,
		config:              config,
		aiAgentRootPidCache: aiAgentRootPidCache,
		counter:             &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	log.Infof("event (%s) decoder run", d.eventType)
	ingestercommon.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"index": strconv.Itoa(d.index), "event_type": d.eventType.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				if d.eventType == common.FILE_EVENT {
					d.flushFileAggEvent()
				}
				d.export(nil)
				continue
			}
			d.counter.InCount++
			switch d.eventType {
			case common.RESOURCE_EVENT:
				event, ok := buffer[i].(*eventapi.ResourceEvent)
				if !ok {
					log.Warning("get resoure event decode queue data type wrong")
					continue
				}
				d.handleResourceEvent(event)
				event.Release()
			case common.FILE_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get file event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
				d.handleFileEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.ALERT_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get alert event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handleAlertEvent(decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.ALERT_RECORD:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get alert record decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handleAlertRecord(decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.K8S_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get k8s event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
				d.handleK8sEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			}
		}
	}
}

func routeProcEventType(e *pb.ProcEvent) common.EventType {
	if e == nil {
		return common.FILE_EVENT
	}
	switch {
	case e.FileOpEventData != nil:
		return common.FILE_MGMT_EVENT
	case e.PermOpEventData != nil:
		return common.PROC_PERM_EVENT
	case e.ProcLifecycleEventData != nil:
		return common.PROC_OPS_EVENT
	default:
		return common.FILE_EVENT
	}
}

func extractProcOpsCommandData(e *pb.ProcEvent) (string, string) {
	if e == nil || e.ProcLifecycleEventData == nil {
		return "", ""
	}
	return string(e.ProcLifecycleEventData.Cmdline), string(e.ProcLifecycleEventData.ExecPath)
}

func extractFileMgmtTargets(d *pb.FileOpEventData) (uint32, uint32, uint32) {
	if d == nil {
		return 0, 0, 0
	}
	switch d.OpType {
	case pb.FileOpType_FileOpChown:
		return d.Uid, d.Gid, 0
	case pb.FileOpType_FileOpChmod:
		return 0, 0, d.Mode
	default:
		return 0, 0, 0
	}
}

func (d *Decoder) initEventStoreCommon(s *dbwriter.EventStore, vtapId uint16, e *pb.ProcEvent) {
	s.Time = uint32(time.Duration(e.StartTime) / time.Second)
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.StartTime = int64(time.Duration(e.StartTime) / time.Microsecond)
	s.EndTime = int64(time.Duration(e.EndTime) / time.Microsecond)
	s.Duration = uint64(e.EndTime - e.StartTime)
	s.PodID = e.PodId
	s.OrgId, s.TeamID = d.orgId, d.teamId

	if e.EventType == pb.EventType_IoEvent {
		s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_IO)
	} else {
		s.SignalSource = uint8(e.EventType)
	}

	s.GProcessID = resolveGProcessID(
		func(pid uint32) uint32 {
			// Event-side gprocess_id follows the same platform-cache timing as L7 logs,
			// so early AI events may transiently remain 0 before the cache catches up.
			return d.platformData.QueryProcessInfo(s.OrgId, vtapId, pid)
		},
		d.aiAgentRootPidCache,
		s.OrgId,
		vtapId,
		e,
	)

	s.VTAPID = vtapId
	s.L3EpcID = d.platformData.QueryVtapEpc0(s.OrgId, vtapId)

	var info *grpc.Info
	if e.PodId != 0 {
		info = d.platformData.QueryPodIdInfo(s.OrgId, e.PodId)
	}

	if info == nil {
		vtapInfo := d.platformData.QueryVtapInfo(s.OrgId, vtapId)
		if vtapInfo != nil {
			vtapIP := net.ParseIP(vtapInfo.Ip)
			if vtapIP != nil {
				if ip4 := vtapIP.To4(); ip4 != nil {
					s.IsIPv4 = true
					s.IP4 = utils.IpToUint32(ip4)
					info = d.platformData.QueryIPV4Infos(s.OrgId, vtapInfo.EpcId, s.IP4)
				} else {
					s.IP6 = vtapIP
					info = d.platformData.QueryIPV6Infos(s.OrgId, vtapInfo.EpcId, s.IP6)
				}
			}
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
		if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
			s.ServiceID = d.platformData.QueryPodService(s.OrgId,
				s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
		}
	} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.OrgId, s.L3EpcID); baseInfo != nil {
		s.RegionID = uint16(baseInfo.RegionID)
	}

	s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), s.L3EpcID)
	customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.PodClusterID, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType), 0)
	s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(customServiceID, s.ServiceID, s.PodGroupID, s.GProcessID, uint32(s.PodClusterID), s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), podGroupType, s.L3EpcID)
	s.AppInstance = strconv.Itoa(int(e.Pid))
}

func (d *Decoder) rawFileWriter() *dbwriter.EventWriter {
	if d.procEventWriters != nil && d.procEventWriters.FileWriter != nil {
		return d.procEventWriters.FileWriter
	}
	return d.eventWriter
}

func (d *Decoder) fileAggWriter() *dbwriter.EventWriter {
	if d.procEventWriters != nil && d.procEventWriters.FileAggWriter != nil {
		return d.procEventWriters.FileAggWriter
	}
	return nil
}

func splitFilePath(fullPath string) (string, string) {
	if idx := strings.LastIndex(fullPath, "/"); idx >= 0 {
		return fullPath[:idx+1], fullPath[idx+1:]
	}
	return "", fullPath
}

func shouldAggregateFileAggEvent(rootPID uint32) bool {
	return rootPID != 0
}

func (d *Decoder) emitFileAggItems(items []*dbwriter.FileAggEventStore) {
	if len(items) == 0 {
		return
	}
	if writer := d.fileAggWriter(); writer != nil {
		for _, item := range items {
			writer.WriteCKItem(item)
		}
		return
	}
	for _, item := range items {
		item.Release()
	}
}

func (d *Decoder) flushFileAggEvent() {
	if d.fileAggReducer == nil {
		return
	}
	d.emitFileAggItems(d.fileAggReducer.Flush())
}

func (d *Decoder) flushFileAggEventByFile(vtapId uint16, rootPID uint32, fullPath string) {
	if d.fileAggReducer == nil || fullPath == "" {
		return
	}
	fileDir, fileName := splitFilePath(fullPath)
	d.emitFileAggItems(d.fileAggReducer.FlushFile(vtapId, rootPID, fileDir, fileName))
}

func (d *Decoder) writeRawFileEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireEventStore()
	s.IsFileEvent = true
	s.StoreEventType = common.FILE_EVENT
	d.initEventStoreCommon(s, vtapId, e)

	ioData := e.IoEventData
	s.EventType = strings.ToLower(ioData.Operation.String())
	s.ProcessKName = string(e.ProcessKname)
	s.FileName = string(ioData.Filename)
	s.Offset = ioData.OffBytes
	s.SyscallThread = e.ThreadId
	s.SyscallCoroutine = e.CoroutineId
	s.FileType = uint8(ioData.FileType)
	s.FileDir = string(ioData.FileDir)
	s.MountSource = string(ioData.MountSource)
	s.MountPoint = string(ioData.MountPoint)
	s.Bytes = ioData.BytesCount
	s.AccessPermission = ioData.AccessPermission
	s.Duration = uint64(s.EndTime - s.StartTime)
	s.RootPID = e.AiAgentRootPid

	d.export(s)
	d.rawFileWriter().Write(s)
	if d.fileAggReducer != nil && shouldAggregateFileAggEvent(s.RootPID) {
		d.emitFileAggItems(d.fileAggReducer.Add(s))
	}
}

func (d *Decoder) writeFileMgmtEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireFileMgmtEventStore()
	d.initEventStoreCommon(&s.EventStore, vtapId, e)

	data := e.FileOpEventData
	opStr := data.OpType.String()
	if strings.HasPrefix(opStr, "FileOp") {
		opStr = opStr[len("FileOp"):]
	}
	s.EventType = strings.ToLower(opStr)
	s.ProcessKName = string(e.ProcessKname)
	fullPath := string(data.Filename)
	s.FileDir, s.FileName = splitFilePath(fullPath)
	s.TargetUID, s.TargetGID, s.TargetMode = extractFileMgmtTargets(data)
	if data.OpType == pb.FileOpType_FileOpChmod {
		s.AccessPermission = data.Mode
	}
	s.RootPID = e.AiAgentRootPid
	s.SyscallThread = e.ThreadId
	s.SyscallCoroutine = e.CoroutineId

	if d.fileMgmtReducer != nil {
		if reduced := d.fileMgmtReducer.Add(s); reduced == nil {
			s.Release()
			return
		}
	}

	if d.procEventWriters != nil && d.procEventWriters.FileMgmtWriter != nil {
		d.procEventWriters.FileMgmtWriter.WriteCKItem(s)
		return
	}
	s.Release()
}

func (d *Decoder) writeProcPermEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireProcPermEventStore()
	d.initEventStoreCommon(&s.EventStore, vtapId, e)

	data := e.PermOpEventData
	s.EventType = strings.ToLower(data.OpType.String())
	s.ProcessKName = string(e.ProcessKname)
	s.Pid = e.Pid
	s.RootPID = e.AiAgentRootPid
	s.OldUID = data.OldUid
	s.OldGID = data.OldGid
	s.NewUID = data.NewUid
	s.NewGID = data.NewGid
	s.SyscallThread = e.ThreadId
	s.SyscallCoroutine = e.CoroutineId

	if d.procEventWriters != nil && d.procEventWriters.ProcPermWriter != nil {
		d.procEventWriters.ProcPermWriter.WriteCKItem(s)
		return
	}
	s.Release()
}

func (d *Decoder) writeProcOpsEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireProcOpsEventStore()
	d.initEventStoreCommon(&s.EventStore, vtapId, e)

	data := e.ProcLifecycleEventData
	s.EventType = strings.ToLower(data.LifecycleType.String())
	s.ProcessKName = string(data.Comm)
	s.Pid = data.Pid
	s.ParentPid = data.ParentPid
	s.RootPID = e.AiAgentRootPid
	s.UID = data.Uid
	s.GID = data.Gid
	s.Cmdline, s.ExecPath = extractProcOpsCommandData(e)
	s.SyscallThread = e.ThreadId
	s.SyscallCoroutine = e.CoroutineId

	if d.procEventWriters != nil && d.procEventWriters.ProcOpsWriter != nil {
		d.procEventWriters.ProcOpsWriter.WriteCKItem(s)
		return
	}
	s.Release()
}

func (d *Decoder) WriteFileEvent(vtapId uint16, e *pb.ProcEvent) {
	switch routeProcEventType(e) {
	case common.FILE_EVENT:
		if e.IoEventData != nil {
			d.writeRawFileEvent(vtapId, e)
		}
	case common.FILE_MGMT_EVENT:
		if e.FileOpEventData != nil {
			d.flushFileAggEventByFile(vtapId, e.AiAgentRootPid, string(e.FileOpEventData.Filename))
		}
		d.writeFileMgmtEvent(vtapId, e)
	case common.PROC_PERM_EVENT:
		d.writeProcPermEvent(vtapId, e)
	case common.PROC_OPS_EVENT:
		d.writeProcOpsEvent(vtapId, e)
	}
}

func resolveGProcessID(queryProcessInfo func(pid uint32) uint32, rootPidCache *AiAgentRootPidCache, orgId, vtapId uint16, e *pb.ProcEvent) uint32 {
	if e == nil {
		return 0
	}

	pid := e.Pid
	if pid == 0 {
		return 0
	}

	rootPid := pid
	if rootPidCache != nil {
		if e.EventType == pb.EventType_ProcLifecycleEvent && e.ProcLifecycleEventData != nil {
			lifecyclePid := e.ProcLifecycleEventData.Pid
			if lifecyclePid != 0 {
				pid = lifecyclePid
			}
			parentPid := e.ProcLifecycleEventData.ParentPid
			if e.ProcLifecycleEventData.LifecycleType == pb.ProcLifecycleType_ProcLifecycleExec {
				if cachedRoot, ok := rootPidCache.Get(orgId, vtapId, pid); ok && cachedRoot != 0 {
					rootPid = cachedRoot
				} else if parentPid != 0 {
					if parentRoot, ok := rootPidCache.Get(orgId, vtapId, parentPid); ok && parentRoot != 0 {
						rootPidCache.Set(orgId, vtapId, pid, parentRoot)
						rootPid = parentRoot
					} else {
						rootPidCache.Set(orgId, vtapId, pid, pid)
						rootPid = pid
					}
				} else {
					rootPidCache.Set(orgId, vtapId, pid, pid)
					rootPid = pid
				}
			} else {
				rootPid = rootPidCache.ResolveRootPid(orgId, vtapId, pid, parentPid)
			}
		} else if cachedRoot, ok := rootPidCache.Get(orgId, vtapId, pid); ok && cachedRoot != 0 {
			rootPid = cachedRoot
		}
	}

	cleanupOnExit := func() {
		if rootPidCache != nil &&
			e.EventType == pb.EventType_ProcLifecycleEvent && e.ProcLifecycleEventData != nil &&
			e.ProcLifecycleEventData.LifecycleType == pb.ProcLifecycleType_ProcLifecycleExit {
			rootPidCache.Delete(orgId, vtapId, pid)
		}
	}

	if rootPid != 0 {
		gprocessID := queryProcessInfo(rootPid)
		if gprocessID != 0 {
			cleanupOnExit()
			return gprocessID
		}
	}

	if rootPid != pid {
		gprocessID := queryProcessInfo(pid)
		if gprocessID != 0 {
			cleanupOnExit()
			return gprocessID
		}
	}

	// Fallback: use ai_agent_root_pid sent by the agent.
	// The agent tracks root AI Agent PIDs in its registry and attaches
	// the root PID to every event from AI Agent processes. This resolves
	// gprocess_id for child/grandchild processes that haven't been
	// synchronized to the process table yet.
	if e.AiAgentRootPid != 0 && e.AiAgentRootPid != pid && e.AiAgentRootPid != rootPid {
		gprocessID := queryProcessInfo(e.AiAgentRootPid)
		if gprocessID != 0 {
			if rootPidCache != nil {
				rootPidCache.Set(orgId, vtapId, pid, e.AiAgentRootPid)
			}
			cleanupOnExit()
			return gprocessID
		}
	}

	// Proc lifecycle (fork/exec/exit) events may arrive before the controller
	// has synchronized the child process into the `process` table. In that
	// window, QueryProcessInfo(child_pid) returns 0 even though the parent is
	// already mapped. Falling back to the parent_pid keeps the lifecycle event
	// attached to the correct AI Agent gprocess_id until the child entry is
	// eventually synced.
	if e.EventType != pb.EventType_ProcLifecycleEvent || e.ProcLifecycleEventData == nil {
		return 0
	}
	parentPid := e.ProcLifecycleEventData.ParentPid
	if parentPid == 0 || parentPid == e.Pid {
		cleanupOnExit()
		return 0
	}
	gprocessID := queryProcessInfo(parentPid)
	if gprocessID == 0 {
		cleanupOnExit()
		return 0
	}
	cleanupOnExit()
	return gprocessID
}

func (d *Decoder) export(item exporterscommon.ExportItem) {
	if d.exporters == nil {
		return
	}
	d.exporters.Put(d.eventType.DataSource(), d.index, item)
}

func (d *Decoder) handleFileEvent(vtapId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbFileEvent := &pb.ProcEvent{}
		if err := pbFileEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.WriteFileEvent(vtapId, pbFileEvent)
	}
}

func uint32ArrayToStr(u32s []uint32) string {
	sb := &strings.Builder{}
	for i, u32 := range u32s {
		sb.WriteString(strconv.Itoa(int(u32)))
		if i < len(u32s)-1 {
			sb.WriteString(SEPARATOR)
		}
	}
	return sb.String()
}

func getAutoInstance(instanceID, instanceType, GProcessID uint32) (uint32, uint8) {
	if GProcessID == 0 || instanceType == uint32(ingestercommon.PodType) {
		return instanceID, uint8(instanceType)
	}
	return GProcessID, ingestercommon.ProcessType
}

func (d *Decoder) handleResourceEvent(event *eventapi.ResourceEvent) {
	s := dbwriter.AcquireEventStore()
	s.IsFileEvent = false
	s.Time = uint32(event.Time)
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.StartTime = event.TimeMilli * 1000 // convert to microsecond
	s.EndTime = s.StartTime

	s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_RESOURCE)
	s.EventType = event.Type
	s.EventDescription = event.Description

	s.OrgId = event.ORGID
	s.TeamID = event.TeamID

	s.GProcessID = event.GProcessID

	if len(event.AttributeSubnetIDs) > 0 {
		s.AttributeNames = append(s.AttributeNames, "subnet_ids")
		s.AttributeValues = append(s.AttributeValues,
			uint32ArrayToStr(event.AttributeSubnetIDs))
	}
	if len(event.AttributeIPs) > 0 {
		s.AttributeNames = append(s.AttributeNames, "ips")
		s.AttributeValues = append(s.AttributeValues,
			strings.Join(event.AttributeIPs, SEPARATOR))

	}
	s.AttributeNames = append(s.AttributeNames, event.AttributeNames...)
	s.AttributeValues = append(s.AttributeValues, event.AttributeValues...)

	podGroupType := uint8(0)
	if event.IfNeedTagged {
		s.Tagged = 1
		resourceInfo := d.platformData.QueryResourceInfo(s.OrgId, event.InstanceType, event.InstanceID, event.PodID)
		if resourceInfo != nil {
			s.RegionID = uint16(resourceInfo.RegionID)
			s.AZID = uint16(resourceInfo.AZID)
			s.L3EpcID = resourceInfo.EpcID
			s.HostID = uint16(resourceInfo.HostID)
			s.PodID = resourceInfo.PodID
			s.PodNodeID = resourceInfo.PodNodeID
			s.PodNSID = uint16(resourceInfo.PodNSID)
			s.PodClusterID = uint16(resourceInfo.PodClusterID)
			s.PodGroupID = resourceInfo.PodGroupID
			podGroupType = resourceInfo.PodGroupType
			s.L3DeviceType = uint8(resourceInfo.DeviceType)
			s.L3DeviceID = resourceInfo.DeviceID
		}
	} else {
		s.Tagged = 0
		s.RegionID = uint16(event.RegionID)
		s.AZID = uint16(event.AZID)
		s.L3EpcID = int32(event.VPCID)
		s.HostID = uint16(event.HostID)
		s.PodID = event.PodID
		s.PodNodeID = event.PodNodeID
		s.PodNSID = uint16(event.PodNSID)
		s.PodClusterID = uint16(event.PodClusterID)
		s.PodGroupID = event.PodGroupID
		podGroupType = event.PodGroupType
		s.L3DeviceType = uint8(event.L3DeviceType)
		s.L3DeviceID = event.L3DeviceID

	}
	s.SubnetID = uint16(event.SubnetID)
	s.IsIPv4 = true
	if ip := net.ParseIP(event.IP); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			s.IP4 = utils.IpToUint32(ip4)
		} else {
			s.IsIPv4 = false
			s.IP6 = ip
		}
	}
	s.AutoInstanceID, s.AutoInstanceType =
		ingestercommon.GetAutoInstance(
			s.PodID,
			s.GProcessID,
			s.PodNodeID,
			s.L3DeviceID,
			uint32(s.SubnetID),
			s.L3DeviceType,
			s.L3EpcID,
		)
	// if resource information is not matched, it will be filled with event(InstanceID, InstanceType, GProcessID) information
	if s.AutoInstanceID == 0 {
		s.AutoInstanceID, s.AutoInstanceType = getAutoInstance(event.InstanceID, event.InstanceType, event.GProcessID)
	}

	if event.InstanceType == uint32(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) {
		s.ServiceID = event.InstanceID
	} else if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
		s.ServiceID = d.platformData.QueryPodService(s.OrgId, s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
	}

	customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.PodClusterID, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType), 0)
	s.AutoServiceID, s.AutoServiceType =
		ingestercommon.GetAutoService(
			customServiceID,
			s.ServiceID,
			s.PodGroupID,
			s.GProcessID,
			uint32(s.PodClusterID),
			s.L3DeviceID,
			uint32(s.SubnetID),
			s.L3DeviceType,
			podGroupType,
			s.L3EpcID,
		)

	d.counter.OutCount++
	d.eventWriter.Write(s)
}

func (d *Decoder) handleAlertEvent(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbAlertEvent := &alert_event.AlertEvent{}
		if err := pbAlertEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.writeAlertEvent(pbAlertEvent)
	}
}

func (d *Decoder) writeAlertEvent(event *alert_event.AlertEvent) {
	s := dbwriter.AcquireAlertEventStore()
	s.Time = event.GetTime()
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())

	s.PolicyId = event.GetPolicyId()
	s.PolicyType = uint8(event.GetPolicyType())
	s.AlertPolicy = event.GetAlertPolicy()
	s.MetricValue = event.GetMetricValue()
	s.MetricValueStr = event.GetMetricValueStr()
	s.EventLevel = uint8(event.GetEventLevel())
	s.TargetTags = event.GetTargetTags()

	s.TagStrKeys = event.GetTagStrKeys()
	s.TagStrValues = event.GetTagStrValues()
	s.TagIntKeys = event.GetTagIntKeys()
	s.TagIntValues = event.GetTagIntValues()
	s.TriggerThreshold = event.GetTriggerThreshold()
	s.CustomTagKeys = event.GetCustomTagKeys()
	s.CustomTagValues = event.GetCustomTagValues()
	s.MetricUnit = event.GetMetricUnit()
	s.XTargetUid = event.GetXTargetUid()
	s.XQueryRegion = event.GetXQueryRegion()

	s.OrgId = uint16(event.GetOrgId())
	s.TeamID = uint16(event.GetTeamId())
	s.UserId = event.GetUserId()

	// New fields
	s.EventId = event.GetEventId()
	s.StartTime = uint32(event.GetStartTime())
	s.EndTime = uint32(event.GetEndTime())
	s.Duration = event.GetDuration()
	s.State = event.GetState()
	s.AlertTime = event.GetAlertTime()

	d.eventWriter.WriteAlertEvent(s)
}

func (d *Decoder) handleAlertRecord(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert record decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbAlertRecord := &alert_event.AlertRecord{}
		if err := pbAlertRecord.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert record unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.writeAlertRecord(pbAlertRecord)
	}
}

func (d *Decoder) writeAlertRecord(event *alert_event.AlertRecord) {
	s := dbwriter.AcquireAlertRecordStore()
	s.Time = event.GetTime()
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())

	s.PolicyId = event.GetPolicyId()
	s.PolicyType = uint8(event.GetPolicyType())
	s.AlertPolicy = event.GetAlertPolicy()
	s.MetricValue = event.GetMetricValue()
	s.MetricValueStr = event.GetMetricValueStr()
	s.EventLevel = uint8(event.GetEventLevel())
	s.TargetTags = event.GetTargetTags()

	s.TagStrKeys = event.GetTagStrKeys()
	s.TagStrValues = event.GetTagStrValues()
	s.TagIntKeys = event.GetTagIntKeys()
	s.TagIntValues = event.GetTagIntValues()
	s.TriggerThreshold = event.GetTriggerThreshold()
	s.CustomTagKeys = event.GetCustomTagKeys()
	s.CustomTagValues = event.GetCustomTagValues()
	s.MetricUnit = event.GetMetricUnit()
	s.XTargetUid = event.GetXTargetUid()
	s.XQueryRegion = event.GetXQueryRegion()

	s.OrgId = uint16(event.GetOrgId())
	s.TeamID = uint16(event.GetTeamId())
	s.UserId = event.GetUserId()

	s.EventId = event.GetEventId()

	d.eventWriter.WriteAlertRecord(s)
}
