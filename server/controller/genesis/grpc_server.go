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

package genesis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/peer"

	tridentcommon "github.com/deepflowys/deepflow/message/common"
	"github.com/deepflowys/deepflow/message/controller"
	"github.com/deepflowys/deepflow/message/trident"
	controllercommon "github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/genesis/common"
	"github.com/deepflowys/deepflow/server/controller/genesis/config"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

func isInterestedHost(tType tridentcommon.TridentType) bool {
	types := []tridentcommon.TridentType{tridentcommon.TridentType_TT_PROCESS, tridentcommon.TridentType_TT_HOST_POD, tridentcommon.TridentType_TT_VM_POD, tridentcommon.TridentType_TT_PHYSICAL_MACHINE, tridentcommon.TridentType_TT_PUBLIC_CLOUD}
	for _, t := range types {
		if t == tType {
			return true
		}
	}
	return false
}

type TridentStats struct {
	VtapID                   uint32
	Version                  uint64
	IP                       string
	Proxy                    string
	ClusterID                string
	LastSeen                 time.Time
	TridentType              tridentcommon.TridentType
	GenesisSyncDataOperation *trident.GenesisPlatformData
}

type SynchronizerServer struct {
	cfg                 config.GenesisConfig
	k8sQueue            queue.QueueWriter
	genesisSyncQueue    queue.QueueWriter
	vtapIDToVersion     map[uint32]uint64
	clusterIDToVersion  map[string]uint64
	vtapIDToLastSeen    map[uint32]time.Time
	clusterIDToLastSeen map[string]time.Time
	tridentStatsMap     map[uint32]TridentStats
}

func NewGenesisSynchronizerServer(cfg config.GenesisConfig, genesisSyncQueue, k8sQueue queue.QueueWriter) *SynchronizerServer {
	return &SynchronizerServer{
		cfg:                 cfg,
		k8sQueue:            k8sQueue,
		genesisSyncQueue:    genesisSyncQueue,
		vtapIDToVersion:     map[uint32]uint64{},
		clusterIDToVersion:  map[string]uint64{},
		vtapIDToLastSeen:    map[uint32]time.Time{},
		clusterIDToLastSeen: map[string]time.Time{},
		tridentStatsMap:     map[uint32]TridentStats{},
	}
}

func (g *SynchronizerServer) GetAgentStats(ip string) []TridentStats {
	result := []TridentStats{}
	for _, value := range g.tridentStatsMap {
		if ip == "" || value.IP == ip {
			result = append(result, value)
		}
	}
	return result
}

func (g *SynchronizerServer) GenesisSync(ctx context.Context, request *trident.GenesisSyncRequest) (*trident.GenesisSyncResponse, error) {
	stats := TridentStats{}
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
		stats.Proxy = peerIP.Addr.String()
	} else {
		remote = peerIP.Addr.String()
	}
	version := request.GetVersion()
	if version == 0 {
		msg := fmt.Sprintf("genesis sync ignore message with version 0 from %s", remote)
		log.Warning(msg)
		return &trident.GenesisSyncResponse{}, errors.New(msg)
	}
	vtapID := request.GetVtapId()
	k8sClusterID := request.GetKubernetesClusterId()
	if vtapID == 0 {
		log.Warningf("genesis sync received message with vtap_id 0 from %s", remote)
	}
	tType := request.GetTridentType()
	stats.IP = remote
	stats.VtapID = vtapID
	stats.Version = version
	stats.TridentType = tType
	stats.LastSeen = time.Now()
	platformData := request.GetPlatformData()
	if vtapID != 0 {
		if tStats, ok := g.tridentStatsMap[vtapID]; ok && platformData == nil {
			stats.GenesisSyncDataOperation = tStats.GenesisSyncDataOperation
		} else {
			stats.GenesisSyncDataOperation = platformData
		}
		g.tridentStatsMap[vtapID] = stats
	}
	if !isInterestedHost(tType) {
		msg := fmt.Sprintf("genesis sync ignore message from %s trident %s vtap_id %v", tType, remote, vtapID)
		log.Debug(msg)
		return &trident.GenesisSyncResponse{Version: &version}, errors.New(msg)
	}
	var localVersion uint64
	if vtapID != 0 {
		now := time.Now()
		if lTime, ok := g.vtapIDToLastSeen[vtapID]; ok {
			lastTime := lTime
			var agingTime float64 = 0
			if g.cfg.AgingTime < g.cfg.VinterfaceAgingTime {
				agingTime = g.cfg.AgingTime
			} else {
				agingTime = g.cfg.VinterfaceAgingTime
			}
			if now.Sub(lastTime).Seconds() >= agingTime {
				g.vtapIDToVersion[vtapID] = 0
			}
		}
		g.vtapIDToLastSeen[vtapID] = now
		localVersion = g.vtapIDToVersion[vtapID]
	}
	if version == localVersion || platformData == nil {
		g.genesisSyncQueue.Put(
			VIFRPCMessage{
				peer:         remote,
				vtapID:       vtapID,
				k8sClusterID: k8sClusterID,
				msgType:      common.TYPE_RENEW,
				message:      request,
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
		g.vtapIDToVersion[vtapID] = version
	}
	return &trident.GenesisSyncResponse{Version: &version}, nil
}

func (g *SynchronizerServer) KubernetesAPISync(ctx context.Context, request *trident.KubernetesAPISyncRequest) (*trident.KubernetesAPISyncResponse, error) {
	stats := TridentStats{}
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
		stats.Proxy = peerIP.Addr.String()
	} else {
		remote = peerIP.Addr.String()
	}
	vtapID := request.GetVtapId()
	if vtapID == 0 {
		log.Warningf("kubernetes api sync received message with vtap_id 0 from %s", remote)
	} else {
		vtapID = request.GetVtapId()
	}
	version := request.GetVersion()
	if version == 0 {
		msg := fmt.Sprintf("kubernetes api sync ignore message with version 0 from ip: %s, vtap id: %d", remote, vtapID)
		log.Warning(msg)
		return &trident.KubernetesAPISyncResponse{}, errors.New(msg)
	}
	clusterID := request.GetClusterId()
	if clusterID == "" {
		msg := fmt.Sprintf("kubernetes api sync ignore message with cluster id null from ip: %s, vtap id: %v", remote, vtapID)
		log.Warningf(msg)
		return &trident.KubernetesAPISyncResponse{}, errors.New(msg)
	}
	entries := request.GetEntries()

	stats.IP = remote
	stats.VtapID = vtapID
	stats.ClusterID = clusterID
	stats.LastSeen = time.Now()
	stats.Version = version
	g.tridentStatsMap[vtapID] = stats
	now := time.Now()
	if vtapID != 0 {
		if lastTime, ok := g.clusterIDToLastSeen[clusterID]; ok {
			if now.Sub(lastTime).Seconds() >= g.cfg.AgingTime {
				g.clusterIDToVersion[clusterID] = 0
			}
		}
		localVersion := g.clusterIDToVersion[clusterID]
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
		g.clusterIDToLastSeen[clusterID] = now
		g.clusterIDToVersion[clusterID] = version
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

func (g *SynchronizerServer) GenesisSharingK8S(ctx context.Context, request *controller.GenesisSharingK8SRequest) (*controller.GenesisSharingK8SResponse, error) {
	clusterID := request.GetClusterId()
	k8sDatas := GenesisService.GetKubernetesData()

	if k8sData, ok := k8sDatas[clusterID]; ok {
		epochStr := k8sData.Epoch.Format(controllercommon.GO_BIRTHDAY)
		return &controller.GenesisSharingK8SResponse{
			Epoch:    &epochStr,
			ErrorMsg: &k8sData.ErrorMSG,
			Entries:  k8sData.Entries,
		}, nil
	}

	return &controller.GenesisSharingK8SResponse{}, errors.New("GenesisSharingK8s api not found k8s data")
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

	return &controller.GenesisSharingSyncResponse{
		Data: &controller.GenesisSyncData{
			Ip:         gSyncIPs,
			Host:       gSyncHosts,
			Lldp:       gSyncLldps,
			Network:    gSyncNetworks,
			Port:       gSyncPorts,
			Vm:         gSyncVms,
			Vpc:        gSyncVpcs,
			Vinterface: gSyncVinterfaces,
		},
	}, nil
}
