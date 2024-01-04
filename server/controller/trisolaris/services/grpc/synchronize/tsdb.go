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
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
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
		AnalyzerConfig:          configure,
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
		pushmanager.Wait()
	}
	log.Info("exit push", r.GetCtrlIp(), r.GetCtrlMac())
	return err
}

var (
	TagNameMapsVersion = uint32(time.Now().Unix()) + uint32(rand.Intn(10000))
	TagNameMapsHash    uint64
)

func (e *TSDBEvent) GetUniversalTagNameMaps(ctx context.Context, in *api.UniversalTagNameMapsRequest) (*api.UniversalTagNameMapsResponse, error) {
	dbCache := trisolaris.GetMetaData().GetDBDataCache()
	resp := generateUniversalTagNameMaps(dbCache)

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

func generateUniversalTagNameMaps(dbCache *metadata.DBDataCache) *api.UniversalTagNameMapsResponse {
	resp := &api.UniversalTagNameMapsResponse{
		DeviceMap:      make([]*api.DeviceMap, len(dbCache.GetChDevicesIDTypeAndName())),
		PodK8SLabelMap: make([]*api.PodK8SLabelMap, len(dbCache.GetPods())),
		PodMap:         make([]*api.IdNameMap, len(dbCache.GetPods())),
		RegionMap:      make([]*api.IdNameMap, len(dbCache.GetRegions())),
		AzMap:          make([]*api.IdNameMap, len(dbCache.GetAZs())),
		PodNodeMap:     make([]*api.IdNameMap, len(dbCache.GetPodNodes())),
		PodNsMap:       make([]*api.IdNameMap, len(dbCache.GetPodNSsIDAndName())),
		PodGroupMap:    make([]*api.IdNameMap, len(dbCache.GetPodGroups())),
		PodClusterMap:  make([]*api.IdNameMap, len(dbCache.GetPodClusters())),
		L3EpcMap:       make([]*api.IdNameMap, len(dbCache.GetVPCs())),
		SubnetMap:      make([]*api.IdNameMap, len(dbCache.GetSubnets())),
		GprocessMap:    make([]*api.IdNameMap, len(dbCache.GetProcesses())),
		VtapMap:        make([]*api.IdNameMap, len(dbCache.GetVTapsIDAndName())),
	}
	for i, pod := range dbCache.GetPods() {
		var labelName, labelValue []string
		for _, label := range strings.Split(pod.Label, ", ") {
			if value := strings.Split(label, ":"); len(value) > 1 {
				labelName = append(labelName, value[0])
				labelValue = append(labelValue, value[1])
			}
		}
		resp.PodK8SLabelMap[i] = &api.PodK8SLabelMap{
			PodId:      proto.Uint32(uint32(pod.ID)),
			LabelName:  labelName,
			LabelValue: labelValue,
		}
		resp.PodMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(pod.ID)),
			Name: proto.String(pod.Name),
		}
	}
	for i, region := range dbCache.GetRegions() {
		resp.RegionMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(region.ID)),
			Name: proto.String(region.Name),
		}
	}
	for i, az := range dbCache.GetAZs() {
		resp.AzMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(az.ID)),
			Name: proto.String(az.Name),
		}
	}
	for i, podNode := range dbCache.GetPodNodes() {
		resp.PodNodeMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(podNode.ID)),
			Name: proto.String(podNode.Name),
		}
	}
	for i, podNS := range dbCache.GetPodNSsIDAndName() {
		resp.PodNsMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(podNS.ID)),
			Name: proto.String(podNS.Name),
		}
	}
	for i, podGroup := range dbCache.GetPodGroups() {
		resp.PodGroupMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(podGroup.ID)),
			Name: proto.String(podGroup.Name),
		}
	}
	for i, podCluster := range dbCache.GetPodClusters() {
		resp.PodClusterMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(podCluster.ID)),
			Name: proto.String(podCluster.Name),
		}
	}
	for i, vpc := range dbCache.GetVPCs() {
		resp.L3EpcMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(vpc.ID)),
			Name: proto.String(vpc.Name),
		}
	}
	for i, subnet := range dbCache.GetSubnets() {
		resp.SubnetMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(subnet.ID)),
			Name: proto.String(subnet.Name),
		}
	}
	for i, process := range dbCache.GetProcesses() {
		resp.GprocessMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(process.ID)),
			Name: proto.String(process.Name),
		}
	}
	for i, vtap := range dbCache.GetVTapsIDAndName() {
		resp.VtapMap[i] = &api.IdNameMap{
			Id:   proto.Uint32(uint32(vtap.ID)),
			Name: proto.String(vtap.Name),
		}
	}
	for i, chDevice := range dbCache.GetChDevicesIDTypeAndName() {
		resp.DeviceMap[i] = &api.DeviceMap{
			Id:   proto.Uint32(uint32(chDevice.DeviceID)),
			Type: proto.Uint32(uint32(chDevice.DeviceType)),
			Name: proto.String(chDevice.Name),
		}
	}

	return resp
}
