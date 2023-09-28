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

package genesis

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	tridentcommon "github.com/deepflowio/deepflow/message/common"
	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	controllercommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"google.golang.org/grpc/peer"
)

func isInterestedHost(tType tridentcommon.TridentType) bool {
	types := []tridentcommon.TridentType{tridentcommon.TridentType_TT_PROCESS, tridentcommon.TridentType_TT_HOST_POD, tridentcommon.TridentType_TT_VM_POD, tridentcommon.TridentType_TT_PHYSICAL_MACHINE, tridentcommon.TridentType_TT_PUBLIC_CLOUD, tridentcommon.TridentType_TT_K8S_SIDECAR}
	for _, t := range types {
		if t == tType {
			return true
		}
	}
	return false
}

type TridentStats struct {
	VtapID                          uint32
	IP                              string
	Proxy                           string
	K8sVersion                      uint64
	SyncVersion                     uint64
	PrometheusVersion               uint64
	K8sLastSeen                     time.Time
	SyncLastSeen                    time.Time
	PrometheusLastSeen              time.Time
	K8sClusterID                    string
	PrometheusClusterID             string
	SyncTridentType                 tridentcommon.TridentType
	GenesisSyncDataOperation        *trident.GenesisPlatformData
	GenesisSyncProcessDataOperation *trident.GenesisProcessData
}

type SynchronizerServer struct {
	cfg                           config.GenesisConfig
	k8sQueue                      queue.QueueWriter
	prometheusQueue               queue.QueueWriter
	genesisSyncQueue              queue.QueueWriter
	vtapIDToVersion               sync.Map
	clusterIDToVersion            sync.Map
	prometheusClusterIDToVersion  sync.Map
	vtapIDToLastSeen              sync.Map
	clusterIDToLastSeen           sync.Map
	prometheusClusterIDToLastSeen sync.Map
	tridentStatsMap               sync.Map
}

func NewGenesisSynchronizerServer(cfg config.GenesisConfig, genesisSyncQueue, k8sQueue, prometheusQueue queue.QueueWriter) *SynchronizerServer {
	return &SynchronizerServer{
		cfg:                           cfg,
		k8sQueue:                      k8sQueue,
		prometheusQueue:               prometheusQueue,
		genesisSyncQueue:              genesisSyncQueue,
		vtapIDToVersion:               sync.Map{},
		clusterIDToVersion:            sync.Map{},
		prometheusClusterIDToVersion:  sync.Map{},
		vtapIDToLastSeen:              sync.Map{},
		clusterIDToLastSeen:           sync.Map{},
		prometheusClusterIDToLastSeen: sync.Map{},
		tridentStatsMap:               sync.Map{},
	}
}

func (g *SynchronizerServer) GetAgentStats(param string) []TridentStats {
	result := []TridentStats{}
	vtapID, err := strconv.Atoi(param)
	if err == nil {
		s, ok := g.tridentStatsMap.Load(uint32(vtapID))
		if !ok {
			return result
		}
		result = append(result, s.(TridentStats))
	} else {
		g.tridentStatsMap.Range(func(_, value interface{}) bool {
			if param == "" || value.(TridentStats).IP == param {
				result = append(result, value.(TridentStats))
			}
			return true
		})
	}
	return result
}

func (g *SynchronizerServer) GenesisSync(ctx context.Context, request *trident.GenesisSyncRequest) (*trident.GenesisSyncResponse, error) {
	k8sClusterID := request.GetKubernetesClusterId()
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
	} else {
		remote = peerIP.Addr.String()
	}
	version := request.GetVersion()
	if version == 0 {
		log.Warningf("genesis sync ignore message with version 0 from %s", remote)
		return &trident.GenesisSyncResponse{}, nil
	}

	vtapID := request.GetVtapId()
	tType := request.GetTridentType()
	if !isInterestedHost(tType) {
		log.Debugf("genesis sync ignore message from %s trident %s vtap_id %v", tType, remote, vtapID)
		return &trident.GenesisSyncResponse{Version: &version}, nil
	}

	var localVersion uint64 = 0
	if vtapID == 0 {
		log.Infof("genesis sync received message with vtap_id 0 from %s", remote)
	} else {
		now := time.Now()
		if lTime, ok := g.vtapIDToLastSeen.Load(vtapID); ok {
			lastTime := lTime.(time.Time)
			var agingTime float64 = 0
			if g.cfg.AgingTime < g.cfg.VinterfaceAgingTime {
				agingTime = g.cfg.AgingTime
			} else {
				agingTime = g.cfg.VinterfaceAgingTime
			}
			if now.Sub(lastTime).Seconds() >= agingTime {
				g.vtapIDToVersion.Store(vtapID, uint64(0))
			}
		}
		g.vtapIDToLastSeen.Store(vtapID, now)
		lVersion, ok := g.vtapIDToVersion.Load(vtapID)
		if ok {
			localVersion = lVersion.(uint64)
		}
	}

	platformData := request.GetPlatformData()
	if version == localVersion || platformData == nil {
		log.Debugf("genesis sync renew version %v from ip %s vtap_id %v", version, remote, vtapID)
		g.genesisSyncQueue.Put(
			VIFRPCMessage{
				peer:    remote,
				vtapID:  vtapID,
				msgType: common.TYPE_RENEW,
				message: request,
			},
		)
		return &trident.GenesisSyncResponse{Version: &localVersion}, nil
	}

	log.Infof("genesis sync received version %v -> %v from ip %s vtap_id %v", localVersion, version, remote, vtapID)
	g.genesisSyncQueue.Put(
		VIFRPCMessage{
			peer:         remote,
			vtapID:       vtapID,
			k8sClusterID: k8sClusterID,
			msgType:      common.TYPE_UPDATE,
			message:      request,
		},
	)

	if vtapID != 0 {
		var stats TridentStats
		if s, ok := g.tridentStatsMap.Load(vtapID); ok {
			stats = s.(TridentStats)
		}
		if sourceIP != "" {
			stats.Proxy = peerIP.Addr.String()
		}
		stats.IP = remote
		stats.VtapID = vtapID
		stats.SyncVersion = version
		stats.SyncTridentType = tType
		stats.SyncLastSeen = time.Now()
		stats.GenesisSyncProcessDataOperation = request.GetProcessData()
		stats.GenesisSyncDataOperation = platformData
		g.tridentStatsMap.Store(vtapID, stats)
		g.vtapIDToVersion.Store(vtapID, version)
	}
	return &trident.GenesisSyncResponse{Version: &version}, nil
}

func (g *SynchronizerServer) KubernetesAPISync(ctx context.Context, request *trident.KubernetesAPISyncRequest) (*trident.KubernetesAPISyncResponse, error) {
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
	} else {
		remote = peerIP.Addr.String()
	}
	vtapID := request.GetVtapId()
	if vtapID == 0 {
		log.Warningf("kubernetes api sync received message with vtap_id 0 from %s", remote)
	}
	version := request.GetVersion()
	if version == 0 {
		log.Warningf("kubernetes api sync ignore message with version 0 from ip: %s, vtap id: %d", remote, vtapID)
		return &trident.KubernetesAPISyncResponse{}, nil
	}
	clusterID := request.GetClusterId()
	if clusterID == "" {
		log.Warningf("kubernetes api sync ignore message with cluster id null from ip: %s, vtap id: %v", remote, vtapID)
		return &trident.KubernetesAPISyncResponse{}, nil
	}
	entries := request.GetEntries()

	var stats TridentStats
	if s, ok := g.tridentStatsMap.Load(vtapID); ok {
		stats = s.(TridentStats)
	}
	if sourceIP != "" {
		stats.Proxy = peerIP.Addr.String()
	}
	stats.IP = remote
	stats.VtapID = vtapID
	stats.K8sClusterID = clusterID
	stats.K8sLastSeen = time.Now()
	stats.K8sVersion = version
	g.tridentStatsMap.Store(vtapID, stats)
	now := time.Now()
	if vtapID != 0 {
		if lastTime, ok := g.clusterIDToLastSeen.Load(clusterID); ok {
			if now.Sub(lastTime.(time.Time)).Seconds() >= g.cfg.AgingTime {
				g.clusterIDToVersion.Store(clusterID, uint64(0))
			}
		}
		var localVersion uint64 = 0
		lVersion, ok := g.clusterIDToVersion.Load(clusterID)
		if ok {
			localVersion = lVersion.(uint64)
		}
		log.Infof("kubernetes api sync received version %v -> %v from ip %s vtap_id %v len %v", localVersion, version, remote, vtapID, len(entries))

		// 如果version有更新，但消息中没有任何kubernetes数据，触发trident重新上报数据
		if localVersion != version && len(entries) == 0 {
			return &trident.KubernetesAPISyncResponse{Version: &localVersion}, nil
		}

		// 正常推送消息到队列中
		g.k8sQueue.Put(K8SRPCMessage{
			peer:    remote,
			vtapID:  vtapID,
			msgType: 0,
			message: request,
		})

		// 更新内存中的last_seen和version
		g.clusterIDToLastSeen.Store(clusterID, now)
		g.clusterIDToVersion.Store(clusterID, version)
		return &trident.KubernetesAPISyncResponse{Version: &version}, nil
	} else {
		log.Infof("kubernetes api sync received version %v from ip %s no vtap_id", version, remote)
		//正常上报数据，才推送消息到队列中
		if len(entries) > 0 {
			g.k8sQueue.Put(K8SRPCMessage{
				peer:    remote,
				vtapID:  vtapID,
				msgType: 0,
				message: request,
			})
		}
		// 采集器未自动发现时，触发trident上报完整数据
		return &trident.KubernetesAPISyncResponse{}, nil
	}
}

func (g *SynchronizerServer) PrometheusAPISync(ctx context.Context, request *trident.PrometheusAPISyncRequest) (*trident.PrometheusAPISyncResponse, error) {
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
	} else {
		remote = peerIP.Addr.String()
	}
	vtapID := request.GetVtapId()
	if vtapID == 0 {
		log.Warningf("prometheus api sync received message with vtap_id 0 from %s", remote)
	}
	version := request.GetVersion()
	if version == 0 {
		log.Warningf("prometheus api sync ignore message with version 0 from ip: %s, vtap id: %d", remote, vtapID)
		return &trident.PrometheusAPISyncResponse{}, nil
	}
	clusterID := request.GetClusterId()
	if clusterID == "" {
		log.Warningf("prometheus api sync ignore message with cluster id null from ip: %s, vtap id: %v", remote, vtapID)
		return &trident.PrometheusAPISyncResponse{}, nil
	}
	entries := request.GetEntries()

	var stats TridentStats
	if s, ok := g.tridentStatsMap.Load(vtapID); ok {
		stats = s.(TridentStats)
	}
	if sourceIP != "" {
		stats.Proxy = peerIP.Addr.String()
	}
	stats.IP = remote
	stats.VtapID = vtapID
	stats.PrometheusClusterID = clusterID
	stats.PrometheusLastSeen = time.Now()
	stats.PrometheusVersion = version
	g.tridentStatsMap.Store(vtapID, stats)
	now := time.Now()
	if vtapID != 0 {
		if lastTime, ok := g.prometheusClusterIDToLastSeen.Load(clusterID); ok {
			if now.Sub(lastTime.(time.Time)).Seconds() >= g.cfg.AgingTime {
				g.prometheusClusterIDToVersion.Store(clusterID, uint64(0))
			}
		}
		var localVersion uint64 = 0
		lVersion, ok := g.prometheusClusterIDToVersion.Load(clusterID)
		if ok {
			localVersion = lVersion.(uint64)
		}
		log.Infof("prometheus api sync received version %v -> %v from ip %s vtap_id %v len %v", localVersion, version, remote, vtapID, len(entries))

		// 如果version有更新，但消息中没有任何kubernetes数据，触发trident重新上报数据
		if localVersion != version && len(entries) == 0 {
			return &trident.PrometheusAPISyncResponse{Version: &localVersion}, nil
		}

		// 正常推送消息到队列中
		g.prometheusQueue.Put(PrometheusMessage{
			peer:    remote,
			vtapID:  vtapID,
			msgType: 0,
			message: request,
		})

		// 更新内存中的last_seen和version
		g.prometheusClusterIDToLastSeen.Store(clusterID, now)
		g.prometheusClusterIDToVersion.Store(clusterID, version)
		return &trident.PrometheusAPISyncResponse{Version: &version}, nil
	} else {
		log.Infof("kubernetes api sync received version %v from ip %s no vtap_id", version, remote)
		//正常上报数据，才推送消息到队列中
		if len(entries) > 0 {
			g.prometheusQueue.Put(PrometheusMessage{
				peer:    remote,
				vtapID:  vtapID,
				msgType: 0,
				message: request,
			})
		}
		// 采集器未自动发现时，触发trident上报完整数据
		return &trident.PrometheusAPISyncResponse{}, nil
	}
}

func (g *SynchronizerServer) GenesisSharingK8S(ctx context.Context, request *controller.GenesisSharingK8SRequest) (*controller.GenesisSharingK8SResponse, error) {
	clusterID := request.GetClusterId()

	if k8sData, ok := GenesisService.GetKubernetesData(clusterID); ok {
		epochStr := k8sData.Epoch.Format(controllercommon.GO_BIRTHDAY)
		return &controller.GenesisSharingK8SResponse{
			Epoch:    &epochStr,
			ErrorMsg: &k8sData.ErrorMSG,
			Entries:  k8sData.Entries,
		}, nil
	}

	return &controller.GenesisSharingK8SResponse{}, nil
}

func (g *SynchronizerServer) GenesisSharingPrometheus(ctx context.Context, request *controller.GenesisSharingPrometheusRequest) (*controller.GenesisSharingPrometheusResponse, error) {
	clusterID := request.GetClusterId()

	if prometheusData, ok := GenesisService.GetPrometheusData(clusterID); ok {
		epochStr := prometheusData.Epoch.Format(controllercommon.GO_BIRTHDAY)
		entriesByte, _ := json.Marshal(prometheusData.Entries)
		return &controller.GenesisSharingPrometheusResponse{
			Epoch:    &epochStr,
			ErrorMsg: &prometheusData.ErrorMSG,
			Entries:  entriesByte,
		}, nil
	}
	return &controller.GenesisSharingPrometheusResponse{}, nil
}

func (g *SynchronizerServer) GenesisSharingSync(ctx context.Context, request *controller.GenesisSharingSyncRequest) (*controller.GenesisSharingSyncResponse, error) {
	gSyncData := GenesisService.GetGenesisSyncData()

	gSyncIPs := []*controller.GenesisSyncIP{}
	for _, ip := range gSyncData.IPLastSeens {
		ipData := ip
		ipLastSeen := ipData.LastSeen.Format(controllercommon.GO_BIRTHDAY)
		gIP := &controller.GenesisSyncIP{
			Masklen:          &ipData.Masklen,
			Ip:               &ipData.IP,
			Lcuuid:           &ipData.Lcuuid,
			VinterfaceLcuuid: &ipData.VinterfaceLcuuid,
			NodeIp:           &ipData.NodeIP,
			LastSeen:         &ipLastSeen,
			VtapId:           &ipData.VtapID,
		}
		gSyncIPs = append(gSyncIPs, gIP)
	}

	gSyncVIPs := []*controller.GenesisSyncVIP{}
	for _, vip := range gSyncData.VIPs {
		vipData := vip
		gVIP := &controller.GenesisSyncVIP{
			Ip:     &vipData.IP,
			Lcuuid: &vipData.Lcuuid,
			NodeIp: &vipData.NodeIP,
			VtapId: &vipData.VtapID,
		}
		gSyncVIPs = append(gSyncVIPs, gVIP)
	}

	gSyncHosts := []*controller.GenesisSyncHost{}
	for _, host := range gSyncData.Hosts {
		hostData := host
		gHost := &controller.GenesisSyncHost{
			Lcuuid:   &hostData.Lcuuid,
			Hostname: &hostData.Hostname,
			Ip:       &hostData.IP,
			NodeIp:   &hostData.NodeIP,
			VtapId:   &hostData.VtapID,
		}
		gSyncHosts = append(gSyncHosts, gHost)
	}

	gSyncLldps := []*controller.GenesisSyncLldp{}
	for _, l := range gSyncData.Lldps {
		lData := l
		lLastSeen := lData.LastSeen.Format(controllercommon.GO_BIRTHDAY)
		gLldp := &controller.GenesisSyncLldp{
			Lcuuid:                &lData.Lcuuid,
			HostIp:                &lData.HostIP,
			HostInterface:         &lData.HostInterface,
			SystemName:            &lData.SystemName,
			ManagementAddress:     &lData.ManagementAddress,
			VinterfaceLcuuid:      &lData.VinterfaceLcuuid,
			VinterfaceDescription: &lData.VinterfaceDescription,
			NodeIp:                &lData.NodeIP,
			LastSeen:              &lLastSeen,
			VtapId:                &lData.VtapID,
		}
		gSyncLldps = append(gSyncLldps, gLldp)
	}

	gSyncNetworks := []*controller.GenesisSyncNetwork{}
	for _, network := range gSyncData.Networks {
		networkData := network
		gNetwork := &controller.GenesisSyncNetwork{
			SegmentationId: &networkData.SegmentationID,
			NetType:        &networkData.NetType,
			External:       &networkData.External,
			Name:           &networkData.Name,
			Lcuuid:         &networkData.Lcuuid,
			VpcLcuuid:      &networkData.VPCLcuuid,
			NodeIp:         &networkData.NodeIP,
			VtapId:         &networkData.VtapID,
		}
		gSyncNetworks = append(gSyncNetworks, gNetwork)
	}

	gSyncPorts := []*controller.GenesisSyncPort{}
	for _, port := range gSyncData.Ports {
		portData := port
		gPort := &controller.GenesisSyncPort{
			Type:          &portData.Type,
			DeviceType:    &portData.DeviceType,
			Lcuuid:        &portData.Lcuuid,
			Mac:           &portData.Mac,
			DeviceLcuuid:  &portData.DeviceLcuuid,
			NetworkLcuuid: &portData.NetworkLcuuid,
			VpcLcuuid:     &portData.VPCLcuuid,
			NodeIp:        &portData.NodeIP,
			VtapId:        &portData.VtapID,
		}
		gSyncPorts = append(gSyncPorts, gPort)
	}

	gSyncVms := []*controller.GenesisSyncVm{}
	for _, vm := range gSyncData.VMs {
		vmData := vm
		vCreateAt := vmData.CreatedAt.Format(controllercommon.GO_BIRTHDAY)
		gVm := &controller.GenesisSyncVm{
			State:        &vmData.State,
			Lcuuid:       &vmData.Lcuuid,
			Name:         &vmData.Name,
			Label:        &vmData.Label,
			VpcLcuuid:    &vmData.VPCLcuuid,
			LaunchServer: &vmData.LaunchServer,
			NodeIp:       &vmData.NodeIP,
			CreatedAt:    &vCreateAt,
			VtapId:       &vmData.VtapID,
		}
		gSyncVms = append(gSyncVms, gVm)
	}

	gSyncVpcs := []*controller.GenesisSyncVpc{}
	for _, vpc := range gSyncData.VPCs {
		vpcData := vpc
		gVpc := &controller.GenesisSyncVpc{
			Lcuuid: &vpcData.Lcuuid,
			Name:   &vpcData.Name,
			NodeIp: &vpcData.NodeIP,
			VtapId: &vpcData.VtapID,
		}
		gSyncVpcs = append(gSyncVpcs, gVpc)
	}

	gSyncVinterfaces := []*controller.GenesisSyncVinterface{}
	for _, v := range gSyncData.Vinterfaces {
		vData := v
		vLastSeen := vData.LastSeen.Format(controllercommon.GO_BIRTHDAY)
		gVinterface := &controller.GenesisSyncVinterface{
			VtapId:              &vData.VtapID,
			Lcuuid:              &vData.Lcuuid,
			NetnsId:             &vData.NetnsID,
			Name:                &vData.Name,
			Ips:                 &vData.IPs,
			Mac:                 &vData.Mac,
			TapName:             &vData.TapName,
			TapMac:              &vData.TapMac,
			DeviceLcuuid:        &vData.DeviceLcuuid,
			DeviceName:          &vData.DeviceName,
			DeviceType:          &vData.DeviceType,
			HostIp:              &vData.HostIP,
			KubernetesClusterId: &vData.KubernetesClusterID,
			NodeIp:              &vData.NodeIP,
			LastSeen:            &vLastSeen,
		}
		gSyncVinterfaces = append(gSyncVinterfaces, gVinterface)
	}

	gSyncProcesses := []*controller.GenesisSyncProcess{}
	for _, p := range gSyncData.Processes {
		pData := p
		pStartTime := pData.StartTime.Format(controllercommon.GO_BIRTHDAY)
		gProcess := &controller.GenesisSyncProcess{
			VtapId:      &pData.VtapID,
			Pid:         &pData.PID,
			Lcuuid:      &pData.Lcuuid,
			NetnsId:     &pData.NetnsID,
			Name:        &pData.Name,
			ProcessName: &pData.ProcessName,
			CmdLine:     &pData.CMDLine,
			User:        &pData.User,
			ContainerId: &pData.ContainerID,
			OsAppTags:   &pData.OSAPPTags,
			NodeIp:      &pData.NodeIP,
			StartTime:   &pStartTime,
		}
		gSyncProcesses = append(gSyncProcesses, gProcess)
	}

	return &controller.GenesisSharingSyncResponse{
		Data: &controller.GenesisSyncData{
			Ip:         gSyncIPs,
			Vip:        gSyncVIPs,
			Host:       gSyncHosts,
			Lldp:       gSyncLldps,
			Network:    gSyncNetworks,
			Port:       gSyncPorts,
			Vm:         gSyncVms,
			Vpc:        gSyncVpcs,
			Vinterface: gSyncVinterfaces,
			Process:    gSyncProcesses,
		},
	}, nil
}
