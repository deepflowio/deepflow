/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/op/go-logging"
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
)

var log = logging.MustGetLogger("trisolaris/synchronize")

type TSDBEvent struct{}

func NewTSDBEvent() *TSDBEvent {
	return &TSDBEvent{}
}

func (e *TSDBEvent) generateConfig(tsdbIP string) *api.Config {
	nodeInfo := trisolaris.GetGNodeInfo()
	pcapDataRetention := nodeInfo.GetPcapDataRetention()
	regionID := nodeInfo.GetRegionIDByTSDBIP(tsdbIP)
	return &api.Config{
		PcapDataRetention: proto.Uint32(pcapDataRetention),
		RegionId:          &regionID,
	}
}

func (e *TSDBEvent) AnalyzerSync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
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
			processName)
	}

	vTapInfo := trisolaris.GetGVTapInfo()
	// 只有roze进入数据节点注册流程，其他节点直接返回数据
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
		Config:                  configure,
	}, nil
}

func (e *TSDBEvent) pushResponse(in *api.SyncRequest) (*api.SyncResponse, error) {
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
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
			processName)
	}
	configure := e.generateConfig(tsdbIP)
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
	vTapIPs := trisolaris.GetGVTapInfo().GetVTapIPs()
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
		Config:                  configure,
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
		pushmanager.Wait()
	}
	log.Info("exit push", r.GetCtrlIp(), r.GetCtrlMac())
	return err
}
