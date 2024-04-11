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
	"hash/fnv"
	"math/rand"
	"time"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
)

var log = logging.MustGetLogger("trisolaris/synchronize")

type TSDBEvent struct{}

func NewTSDBEvent() *TSDBEvent {
	return &TSDBEvent{}
}

func (e *TSDBEvent) generateConfig(tsdbIP string) *api.AnalyzerConfig {
	nodeInfo := trisolaris.GetGNodeInfo()
	regionID := nodeInfo.GetRegionIDByTSDBIP(tsdbIP)
	analyzerID := nodeInfo.GetTSDBID(tsdbIP)
	return &api.AnalyzerConfig{
		RegionId:   &regionID,
		AnalyzerId: &analyzerID,
	}
}

func (e *TSDBEvent) AnalyzerSync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	if trisolaris.IsTheDataReady() == false {
		log.Info("The data has not been initialized yet")
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, nil
	}
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
	if nodeInfo == nil {
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, nil
	}
	versionPlatformData := trisolaris.GetIngesterPlatformDataVersion()
	versionGroups := trisolaris.GetIngesterGroupProtoVersion()
	versionPolicy := trisolaris.GetIngesterPolicyVersion()
	if versionPlatformData != in.GetVersionPlatformData() ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Infof("ctrl_ip is %s, (platform data version %d -> %d), "+
			"(acl version %d -> %d), (groups version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			processName)
	}

	vTapInfo := trisolaris.GetGVTapInfo(DEFAULT_ORG_ID)
	// 只有ingester进入数据节点注册流程，其他节点直接返回数据
	if processName == TSDB_PROCESS_NAME {
		log.Infof(
			"ctrl_ip:%s, cpu_num:%d, memory_size:%d, arch:%s, os:%s, "+
				"kernel_version:%s, pcap_data_mount_path:%s",
			tsdbIP, in.GetCpuNum(), in.GetMemorySize(),
			in.GetArch(), in.GetOs(),
			in.GetKernelVersion(),
			in.GetTsdbReportInfo())
		tsdbCache := nodeInfo.GetTSDBCache(tsdbIP)
		// 数据节点注册
		if tsdbCache == nil {
			nodeInfo.RegisterTSDB(in)
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

	configure := e.generateConfig(tsdbIP)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = trisolaris.GetIngesterPlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = trisolaris.GetIngesterGroupProtoStr()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = trisolaris.GetIngesterPolicyStr()
	}
	podIPs := trisolaris.GetIngesterPodIPs()
	vTapIPs := trisolaris.GetIngesterVTapIPs()
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
	if trisolaris.IsTheDataReady() == false {
		return &api.SyncResponse{
			Status: &STATUS_FAILED,
		}, fmt.Errorf("The data has not been initialized yet")
	}
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
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
	versionPlatformData := trisolaris.GetIngesterPlatformDataVersion()
	versionGroups := trisolaris.GetIngesterGroupProtoVersion()
	versionPolicy := trisolaris.GetIngesterPolicyVersion()
	if versionPlatformData != in.GetVersionPlatformData() ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Infof("push ctrl_ip is %s, (platform data version %d -> %d), "+
			"(acl version %d -> %d), (groups version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			processName)
	}
	configure := e.generateConfig(tsdbIP)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = trisolaris.GetIngesterPlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = trisolaris.GetIngesterGroupProtoStr()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = trisolaris.GetIngesterPolicyStr()
	}
	podIPs := trisolaris.GetIngesterPodIPs()
	vTapIPs := trisolaris.GetIngesterVTapIPs()
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
	for {
		response, err := e.pushResponse(r)
		if err != nil {
			log.Error(err)
			in.Send(response)
			break
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
			break
		}
		pushmanager.IngesterWait()
	}
	log.Info("exit ingester push", r.GetCtrlIp(), r.GetCtrlMac())
	return err
}

var (
	TagNameMapsVersion = uint32(time.Now().Unix()) + uint32(rand.Intn(10000))
	TagNameMapsHash    uint64
)

func (e *TSDBEvent) GetUniversalTagNameMaps(ctx context.Context, in *api.UniversalTagNameMapsRequest) (*api.UniversalTagNameMapsResponse, error) {
	resp := trisolaris.GetIngesterUniversalTagNames()
	resp.Version = nil
	respStr, err := resp.Marshal()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	h64 := fnv.New64()
	h64.Write(respStr)
	if h64.Sum64() != TagNameMapsHash {
		TagNameMapsVersion += 1
		TagNameMapsHash = h64.Sum64()
	}
	resp.Version = proto.Uint32(TagNameMapsVersion)

	return resp, nil
}
