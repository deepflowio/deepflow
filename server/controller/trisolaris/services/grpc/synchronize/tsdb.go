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

package synchronize

import (
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.synchronize")

type TSDBEvent struct{}

func NewTSDBEvent() *TSDBEvent {
	return &TSDBEvent{}
}

func (e *TSDBEvent) generateConfig(tsdbIP string, orgID int) *api.AnalyzerConfig {
	nodeInfo := trisolaris.GetTrisolaris(orgID).GetNodeInfo()
	regionID := nodeInfo.GetRegionIDByTSDBIP(tsdbIP)
	analyzerID := nodeInfo.GetTSDBID(tsdbIP)
	return &api.AnalyzerConfig{
		RegionId:   &regionID,
		AnalyzerId: &analyzerID,
	}
}

func (e *TSDBEvent) AnalyzerSync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	orgID := int(in.GetOrgId())
	if orgID == 0 {
		orgID = DEFAULT_ORG_ID
	}
	orgTrisolaris := trisolaris.GetTrisolaris(orgID)
	if orgTrisolaris == nil {
		log.Errorf("not found trisolaris data", logger.NewORGPrefix(orgID))
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, nil
	}
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := orgTrisolaris.GetNodeInfo()
	if nodeInfo == nil {
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, nil
	}
	versionPlatformData := nodeInfo.GetPlatformDataVersion()
	versionGroups := nodeInfo.GetGroupsVersion()
	versionPolicy := nodeInfo.GetPolicyVersion()
	if versionPlatformData != in.GetVersionPlatformData() ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Infof("ctrl_ip is %s, (platform data version %d -> %d), "+
			"(acl version %d -> %d), (groups version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			processName, logger.NewORGPrefix(orgID))
	}

	vTapInfo := orgTrisolaris.GetVTapInfo()
	// 只有ingester进入数据节点注册流程，其他节点直接返回数据
	if processName == TSDB_PROCESS_NAME {
		log.Infof(
			"ctrl_ip:%s, cpu_num:%d, memory_size:%d, arch:%s, os:%s, "+
				"kernel_version:%s, pcap_data_mount_path:%s",
			tsdbIP, in.GetCpuNum(), in.GetMemorySize(),
			in.GetArch(), in.GetOs(),
			in.GetKernelVersion(),
			in.GetTsdbReportInfo(), logger.NewORGPrefix(orgID))
		tsdbCache := nodeInfo.GetTSDBCache(tsdbIP)
		// 数据节点注册
		if tsdbCache == nil {
			// Only the default organization registers with tsdb
			if orgID == DEFAULT_ORG_ID {
				nodeInfo.RegisterTSDB(in)
			}
			return &api.SyncResponse{
				Status: &STATUS_FAILED,
			}, nil
		}
		if in.GetCommunicationVtaps() != nil {
			vTapInfo.UpdateTSDBVTapInfo(in.GetCommunicationVtaps(), tsdbIP)
		}
		pcapDataMountPath := ""
		if in.GetTsdbReportInfo() != nil {
			pcapDataMountPath = in.GetTsdbReportInfo().GetPcapDataMountPath()
		}
		tsdbCache.UpdateSystemInfo(
			int(in.GetCpuNum()),
			int64(in.GetMemorySize()),
			in.GetArch(),
			in.GetOs(),
			in.GetKernelVersion(),
			pcapDataMountPath,
			in.GetHost())
		tsdbCache.UpdateSyncedAt(time.Now())
	}

	configure := e.generateConfig(tsdbIP, orgID)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = nodeInfo.GetPlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = nodeInfo.GetGroups()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = nodeInfo.GetPolicy()
	}
	podIPs := nodeInfo.GetPodIPs()
	vTapIPs := vTapInfo.GetVTapIPs()
	localServers := nodeInfo.GetLocalControllers()
	return &api.SyncResponse{
		Status:                  &STATUS_SUCCESS,
		PlatformData:            platformData,
		Groups:                  groups,
		FlowAcls:                acls,
		PodIps:                  podIPs,
		VtapIps:                 vTapIPs,
		VersionPlatformData:     proto.Uint64(versionPlatformData),
		VersionGroups:           proto.Uint64(versionGroups),
		VersionAcls:             proto.Uint64(versionPolicy),
		DeepflowServerInstances: localServers,
		AnalyzerConfig:          configure,
	}, nil
}

func (e *TSDBEvent) pushResponse(in *api.SyncRequest) (*api.SyncResponse, error) {
	orgID := int(in.GetOrgId())
	if orgID == 0 {
		orgID = DEFAULT_ORG_ID
	}
	orgTrisolaris := trisolaris.GetTrisolaris(orgID)
	if orgTrisolaris == nil {
		log.Errorf("not found trisolaris data", logger.NewORGPrefix(orgID))
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, nil
	}
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := orgTrisolaris.GetNodeInfo()
	if nodeInfo == nil {
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, fmt.Errorf("no find nodeInfo(%s)", tsdbIP)
	}
	if processName == TSDB_PROCESS_NAME {
		tsdbCache := nodeInfo.GetTSDBCache(tsdbIP)
		if tsdbCache == nil {
			return &api.SyncResponse{
				Status: &STATUS_FAILED,
			}, fmt.Errorf("no find tsdb(%s) cache", tsdbIP)
		}
	}
	versionPlatformData := nodeInfo.GetPlatformDataVersion()
	versionGroups := nodeInfo.GetGroupsVersion()
	versionPolicy := nodeInfo.GetPolicyVersion()
	if versionPlatformData != in.GetVersionPlatformData() ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Infof("push ctrl_ip is %s, (platform data version %d -> %d), "+
			"(acl version %d -> %d), (groups version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			processName, logger.NewORGPrefix(orgID))
	}
	configure := e.generateConfig(tsdbIP, orgID)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = nodeInfo.GetPlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = nodeInfo.GetGroups()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = nodeInfo.GetPolicy()
	}
	podIPs := nodeInfo.GetPodIPs()
	vTapIPs := orgTrisolaris.GetVTapInfo().GetVTapIPs()
	localServers := nodeInfo.GetLocalControllers()
	return &api.SyncResponse{
		Status:                  &STATUS_SUCCESS,
		PlatformData:            platformData,
		Groups:                  groups,
		FlowAcls:                acls,
		PodIps:                  podIPs,
		VtapIps:                 vTapIPs,
		VersionPlatformData:     proto.Uint64(versionPlatformData),
		VersionGroups:           proto.Uint64(versionGroups),
		VersionAcls:             proto.Uint64(versionPolicy),
		DeepflowServerInstances: localServers,
		AnalyzerConfig:          configure,
	}, nil
}

func (e *TSDBEvent) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	var err error
	orgID := int(r.GetOrgId())
	if orgID == 0 {
		orgID = DEFAULT_ORG_ID
	}
	for {
		response, err := e.pushResponse(r)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
			in.Send(response)
			break
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
			break
		}
		pushmanager.IngesterWait(orgID)
	}
	log.Info("exit ingester push", r.GetCtrlIp(), r.GetCtrlMac(), logger.NewORGPrefix(orgID))
	return err
}

func (e *TSDBEvent) GetUniversalTagNameMaps(ctx context.Context, in *api.UniversalTagNameMapsRequest) (*api.UniversalTagNameMapsResponse, error) {
	orgID := int(in.GetOrgId())
	if orgID == 0 {
		orgID = DEFAULT_ORG_ID
	}
	orgTrisolaris := trisolaris.GetTrisolaris(orgID)
	if orgTrisolaris == nil {
		log.Errorf("not found trisolaris data", logger.NewORGPrefix(orgID))
		return &api.UniversalTagNameMapsResponse{}, nil
	}
	nodeInfo := orgTrisolaris.GetNodeInfo()
	if nodeInfo == nil {
		return &api.UniversalTagNameMapsResponse{}, nil
	}

	resp := nodeInfo.GetUniversalTagNames()
	log.Infof("UniversalTagNameVersion %d", resp.GetVersion(), logger.NewORGPrefix(orgID))
	return resp, nil
}

func (e *TSDBEvent) GetOrgIDs(ctx context.Context, in *api.OrgIDsRequest) (*api.OrgIDsResponse, error) {
	return trisolaris.GetOrgIDsData(), nil
}
