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

package genesis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/op/go-logging"
	"google.golang.org/grpc"

	api "github.com/deepflowio/deepflow/message/controller"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	genesiscommon "github.com/deepflowio/deepflow/server/controller/genesis/common"
	gconfig "github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/statsd"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("genesis")
var GenesisService *Genesis
var Synchronizer *SynchronizerServer

type Genesis struct {
	mutex            sync.RWMutex
	grpcPort         string
	grpcMaxMSGLength int
	listenPort       int
	listenNodePort   int
	cfg              gconfig.GenesisConfig
	genesisSyncData  atomic.Value
	kubernetesData   sync.Map
	prometheusData   sync.Map
	genesisStatsd    statsd.GenesisStatsd
}

func NewGenesis(cfg *config.ControllerConfig) *Genesis {
	var sData atomic.Value
	sData.Store(GenesisSyncData{})
	GenesisService = &Genesis{
		mutex:            sync.RWMutex{},
		grpcPort:         cfg.GrpcPort,
		grpcMaxMSGLength: cfg.GrpcMaxMessageLength,
		listenPort:       cfg.ListenPort,
		listenNodePort:   cfg.ListenNodePort,
		cfg:              cfg.GenesisCfg,
		genesisSyncData:  sData,
		kubernetesData:   sync.Map{},
		prometheusData:   sync.Map{},
		genesisStatsd: statsd.GenesisStatsd{
			K8SInfoDelay: make(map[string][]float64),
		},
	}
	return GenesisService
}

func (g *Genesis) Start() {
	ctx := context.Context(context.Background())
	genesisSyncDataChan := make(chan GenesisSyncData)
	kubernetesDataChan := make(chan map[int]map[string]KubernetesInfo)
	prometheusDataChan := make(chan map[int]map[string]PrometheusInfo)
	sQueue := queue.NewOverwriteQueue("genesis-sync-data", g.cfg.QueueLengths)
	kQueue := queue.NewOverwriteQueue("genesis-k8s-data", g.cfg.QueueLengths)
	pQueue := queue.NewOverwriteQueue("genesis-prometheus-data", g.cfg.QueueLengths)

	// 由于可能需要从数据库恢复数据，这里先启动监听
	go g.receiveGenesisSyncData(genesisSyncDataChan)
	go g.receiveKubernetesData(kubernetesDataChan)
	go g.receivePrometheusData(prometheusDataChan)

	go func() {
		Synchronizer = NewGenesisSynchronizerServer(g.cfg, sQueue, kQueue, pQueue)

		vStorage := NewSyncStorage(g.cfg, genesisSyncDataChan, ctx)
		vStorage.Start()
		vUpdater := NewGenesisSyncRpcUpdater(vStorage, sQueue, g.cfg, ctx)
		vUpdater.Start()

		kStorage := NewKubernetesStorage(g.listenPort, g.listenNodePort, g.cfg, kubernetesDataChan, ctx)
		kStorage.Start()
		kUpdater := NewKubernetesRpcUpdater(kStorage, kQueue, ctx)
		kUpdater.Start()

		pStorage := NewPrometheusStorage(g.cfg, prometheusDataChan, ctx)
		pStorage.Start()
		pUpdater := NewPrometheuspInfoRpcUpdater(pStorage, pQueue, ctx)
		pUpdater.Start()
	}()
}

func (g *Genesis) GetStatter() statsd.StatsdStatter {
	return statsd.StatsdStatter{
		Element: statsd.GetGenesisStatsd(g.genesisStatsd),
	}
}

func (g *Genesis) receiveGenesisSyncData(sChan chan GenesisSyncData) {
	for {
		select {
		case s := <-sChan:
			g.genesisSyncData.Store(s)
		}
	}
}

func (g *Genesis) GetGenesisSyncData(orgID int) GenesisSyncDataResponse {
	syncData := g.genesisSyncData.Load().(GenesisSyncData)
	return GenesisSyncDataResponse{
		IPLastSeens: syncData.IPLastSeens[orgID],
		VIPs:        syncData.VIPs[orgID],
		VMs:         syncData.VMs[orgID],
		VPCs:        syncData.VPCs[orgID],
		Hosts:       syncData.Hosts[orgID],
		Lldps:       syncData.Lldps[orgID],
		Ports:       syncData.Ports[orgID],
		Networks:    syncData.Networks[orgID],
		Vinterfaces: syncData.Vinterfaces[orgID],
		Processes:   syncData.Processes[orgID],
	}
}

func (g *Genesis) GetGenesisSyncResponse(orgID int) (GenesisSyncDataResponse, error) {
	retGenesisSyncData := GenesisSyncDataResponse{}

	db, err := mysql.GetDB(orgID)
	if err != nil {
		log.Errorf("get org id (%d) mysql session failed", orgID)
		return retGenesisSyncData, err
	}

	var controllers []mysql.Controller
	var azControllerConns []mysql.AZControllerConnection
	var currentRegion string

	db.Where("state <> ?", common.CONTROLLER_STATE_EXCEPTION).Find(&controllers)
	db.Find(&azControllerConns)

	controllerIPToRegion := make(map[string]string)
	for _, conn := range azControllerConns {
		if os.Getenv(common.NODE_IP_KEY) == conn.ControllerIP {
			currentRegion = conn.Region
		}
		controllerIPToRegion[conn.ControllerIP] = conn.Region
	}

	syncIPLcuuidSet := map[string]bool{}
	syncVIPLcuuidSet := map[string]bool{}
	syncHostLcuuidSet := map[string]bool{}
	syncLLDPLcuuidSet := map[string]bool{}
	syncNetworkLcuuidSet := map[string]bool{}
	syncPortLcuuidSet := map[string]bool{}
	syncVMLcuuidSet := map[string]bool{}
	syncVPCLcuuidSet := map[string]bool{}
	syncVinterfaceLcuuidSet := map[string]bool{}
	syncProcessLcuuidSet := map[string]bool{}
	for _, controller := range controllers {
		// skip other region controller
		if region, ok := controllerIPToRegion[controller.IP]; !ok || region != currentRegion {
			continue
		}

		// get effective vtap ids in current controller
		var storages []model.GenesisStorage
		db.Where("node_ip = ?", controller.IP).Find(&storages)
		vtapIDMap := map[uint32]int{0: 0}
		for _, storage := range storages {
			vtapIDMap[storage.VtapID] = 0
		}

		// use pod ip communication in internal region
		serverIP := controller.PodIP
		if serverIP == "" {
			serverIP = controller.IP
		}
		grpcServer := net.JoinHostPort(serverIP, g.grpcPort)
		conn, err := grpc.Dial(grpcServer, grpc.WithInsecure(), grpc.WithMaxMsgSize(g.grpcMaxMSGLength))
		if err != nil {
			msg := "create grpc connection faild:" + err.Error()
			log.Error(msg)
			return retGenesisSyncData, errors.New(msg)
		}
		defer conn.Close()

		client := api.NewControllerClient(conn)
		reqOrgID := uint32(orgID)
		req := &api.GenesisSharingSyncRequest{
			OrgId: &reqOrgID,
		}
		ret, err := client.GenesisSharingSync(context.Background(), req)
		if err != nil {
			msg := fmt.Sprintf("get genesis sharing sync faild (%s)", err.Error())
			log.Warning(msg)
			return retGenesisSyncData, errors.New(msg)
		}

		genesisSyncData := ret.GetData()
		genesisSyncIPs := genesisSyncData.GetIp()
		for _, ip := range genesisSyncIPs {
			if _, ok := vtapIDMap[ip.GetVtapId()]; !ok {
				continue
			}
			sIPLcuuid := ip.GetLcuuid()
			if _, ok := syncIPLcuuidSet[sIPLcuuid]; ok {
				continue
			}
			syncIPLcuuidSet[sIPLcuuid] = false
			ipLastSeenStr := ip.GetLastSeen()
			ipLastSeen, _ := time.ParseInLocation(common.GO_BIRTHDAY, ipLastSeenStr, time.Local)
			retGenesisSyncData.IPLastSeens = append(retGenesisSyncData.IPLastSeens, model.GenesisIP{
				Masklen:          ip.GetMasklen(),
				IP:               ip.GetIp(),
				Lcuuid:           sIPLcuuid,
				VinterfaceLcuuid: ip.GetVinterfaceLcuuid(),
				NodeIP:           ip.GetNodeIp(),
				LastSeen:         ipLastSeen,
			})
		}

		genesisSyncVIPs := genesisSyncData.GetVip()
		for _, vip := range genesisSyncVIPs {
			vtapID := vip.GetVtapId()
			if _, ok := vtapIDMap[vtapID]; !ok {
				continue
			}
			sVIPLcuuid := vip.GetLcuuid()
			if _, ok := syncVIPLcuuidSet[sVIPLcuuid]; ok {
				continue
			}
			syncVIPLcuuidSet[sVIPLcuuid] = false
			retGenesisSyncData.VIPs = append(retGenesisSyncData.VIPs, model.GenesisVIP{
				VtapID: vtapID,
				IP:     vip.GetIp(),
				Lcuuid: sVIPLcuuid,
				NodeIP: vip.GetNodeIp(),
			})
		}

		genesisSyncHosts := genesisSyncData.GetHost()
		for _, host := range genesisSyncHosts {
			if _, ok := vtapIDMap[host.GetVtapId()]; !ok {
				continue
			}
			sHostLcuuid := host.GetLcuuid()
			if _, ok := syncHostLcuuidSet[sHostLcuuid]; ok {
				continue
			}
			syncHostLcuuidSet[sHostLcuuid] = false
			retGenesisSyncData.Hosts = append(retGenesisSyncData.Hosts, model.GenesisHost{
				Lcuuid:   sHostLcuuid,
				Hostname: host.GetHostname(),
				IP:       host.GetIp(),
				NodeIP:   host.GetNodeIp(),
			})
		}

		genesisSyncLldps := genesisSyncData.GetLldp()
		for _, l := range genesisSyncLldps {
			if _, ok := vtapIDMap[l.GetVtapId()]; !ok {
				continue
			}
			sLLDPLcuuid := l.GetLcuuid()
			if _, ok := syncLLDPLcuuidSet[sLLDPLcuuid]; ok {
				continue
			}
			syncLLDPLcuuidSet[sLLDPLcuuid] = false
			lLastSeenStr := l.GetLastSeen()
			lLastSeen, _ := time.ParseInLocation(common.GO_BIRTHDAY, lLastSeenStr, time.Local)
			retGenesisSyncData.Lldps = append(retGenesisSyncData.Lldps, model.GenesisLldp{
				Lcuuid:                sLLDPLcuuid,
				HostIP:                l.GetHostIp(),
				HostInterface:         l.GetHostInterface(),
				SystemName:            l.GetSystemName(),
				ManagementAddress:     l.GetManagementAddress(),
				VinterfaceLcuuid:      l.GetVinterfaceLcuuid(),
				VinterfaceDescription: l.GetVinterfaceDescription(),
				NodeIP:                l.GetNodeIp(),
				LastSeen:              lLastSeen,
			})
		}

		genesisSyncNetworks := genesisSyncData.GetNetwork()
		for _, network := range genesisSyncNetworks {
			if _, ok := vtapIDMap[network.GetVtapId()]; !ok {
				continue
			}
			sNetworkLcuuid := network.GetLcuuid()
			if _, ok := syncNetworkLcuuidSet[sNetworkLcuuid]; ok {
				continue
			}
			syncNetworkLcuuidSet[sNetworkLcuuid] = false
			retGenesisSyncData.Networks = append(retGenesisSyncData.Networks, model.GenesisNetwork{
				SegmentationID: network.GetSegmentationId(),
				NetType:        network.GetNetType(),
				External:       network.GetExternal(),
				Name:           network.GetName(),
				Lcuuid:         sNetworkLcuuid,
				VPCLcuuid:      network.GetVpcLcuuid(),
				NodeIP:         network.GetNodeIp(),
			})
		}

		genesisSyncPorts := genesisSyncData.GetPort()
		for _, port := range genesisSyncPorts {
			if _, ok := vtapIDMap[port.GetVtapId()]; !ok {
				continue
			}
			sPortLcuuid := port.GetLcuuid()
			if _, ok := syncPortLcuuidSet[sPortLcuuid]; ok {
				continue
			}
			syncPortLcuuidSet[sPortLcuuid] = false
			retGenesisSyncData.Ports = append(retGenesisSyncData.Ports, model.GenesisPort{
				Type:          port.GetType(),
				DeviceType:    port.GetDeviceType(),
				Lcuuid:        sPortLcuuid,
				Mac:           port.GetMac(),
				DeviceLcuuid:  port.GetDeviceLcuuid(),
				NetworkLcuuid: port.GetNetworkLcuuid(),
				VPCLcuuid:     port.GetVpcLcuuid(),
				NodeIP:        port.GetNodeIp(),
			})
		}

		genesisSyncVms := genesisSyncData.GetVm()
		for _, vm := range genesisSyncVms {
			if _, ok := vtapIDMap[vm.GetVtapId()]; !ok {
				continue
			}
			sVMLcuuid := vm.GetLcuuid()
			if _, ok := syncVMLcuuidSet[sVMLcuuid]; ok {
				continue
			}
			syncVMLcuuidSet[sVMLcuuid] = false
			vCreatedAtStr := vm.GetCreatedAt()
			vCreatedAt, _ := time.ParseInLocation(common.GO_BIRTHDAY, vCreatedAtStr, time.Local)
			retGenesisSyncData.VMs = append(retGenesisSyncData.VMs, model.GenesisVM{
				State:        vm.GetState(),
				Lcuuid:       sVMLcuuid,
				Name:         vm.GetName(),
				Label:        vm.GetLabel(),
				VPCLcuuid:    vm.GetVpcLcuuid(),
				LaunchServer: vm.GetLaunchServer(),
				NodeIP:       vm.GetNodeIp(),
				CreatedAt:    vCreatedAt,
			})
		}

		genesisSyncVpcs := genesisSyncData.GetVpc()
		for _, vpc := range genesisSyncVpcs {
			if _, ok := vtapIDMap[vpc.GetVtapId()]; !ok {
				continue
			}
			sVPCLcuuid := vpc.GetLcuuid()
			if _, ok := syncVPCLcuuidSet[sVPCLcuuid]; ok {
				continue
			}
			syncVPCLcuuidSet[sVPCLcuuid] = false
			retGenesisSyncData.VPCs = append(retGenesisSyncData.VPCs, model.GenesisVpc{
				Lcuuid: sVPCLcuuid,
				Name:   vpc.GetName(),
				NodeIP: vpc.GetNodeIp(),
			})
		}

		genesisSyncVinterfaces := genesisSyncData.GetVinterface()
		for _, v := range genesisSyncVinterfaces {
			if _, ok := vtapIDMap[v.GetVtapId()]; !ok {
				continue
			}
			sVinterfaceLcuuid := v.GetLcuuid()
			if _, ok := syncVinterfaceLcuuidSet[sVinterfaceLcuuid]; ok {
				continue
			}
			syncVinterfaceLcuuidSet[sVinterfaceLcuuid] = false
			vLastSeenStr := v.GetLastSeen()
			vpLastSeen, _ := time.ParseInLocation(common.GO_BIRTHDAY, vLastSeenStr, time.Local)
			retGenesisSyncData.Vinterfaces = append(retGenesisSyncData.Vinterfaces, model.GenesisVinterface{
				VtapID:              v.GetVtapId(),
				Lcuuid:              sVinterfaceLcuuid,
				NetnsID:             v.GetNetnsId(),
				Name:                v.GetName(),
				IPs:                 v.GetIps(),
				Mac:                 v.GetMac(),
				TapName:             v.GetTapName(),
				TapMac:              v.GetTapMac(),
				DeviceLcuuid:        v.GetDeviceLcuuid(),
				DeviceName:          v.GetDeviceName(),
				DeviceType:          v.GetDeviceType(),
				IFType:              v.GetIfType(),
				HostIP:              v.GetHostIp(),
				KubernetesClusterID: v.GetKubernetesClusterId(),
				NodeIP:              v.GetNodeIp(),
				LastSeen:            vpLastSeen,
			})
		}

		genesisSyncProcesses := genesisSyncData.GetProcess()
		for _, p := range genesisSyncProcesses {
			if _, ok := vtapIDMap[p.GetVtapId()]; !ok {
				continue
			}
			sProcessLcuuid := p.GetLcuuid()
			if _, ok := syncProcessLcuuidSet[sProcessLcuuid]; ok {
				continue
			}
			syncProcessLcuuidSet[sProcessLcuuid] = false
			pStartTimeStr := p.GetStartTime()
			pStartTime, _ := time.ParseInLocation(common.GO_BIRTHDAY, pStartTimeStr, time.Local)
			retGenesisSyncData.Processes = append(retGenesisSyncData.Processes, model.GenesisProcess{
				VtapID:      p.GetVtapId(),
				PID:         p.GetPid(),
				Lcuuid:      sProcessLcuuid,
				NetnsID:     p.GetNetnsId(),
				Name:        p.GetName(),
				ProcessName: p.GetProcessName(),
				CMDLine:     p.GetCmdLine(),
				ContainerID: p.GetContainerId(),
				User:        p.GetUser(),
				OSAPPTags:   p.GetOsAppTags(),
				NodeIP:      p.GetNodeIp(),
				StartTime:   pStartTime,
			})
		}
	}
	return retGenesisSyncData, nil
}

func (g *Genesis) getServerIPs(orgID int) ([]string, error) {
	db, err := mysql.GetDB(orgID)
	if err != nil {
		log.Errorf("get org id (%d) mysql session failed", orgID)
		return []string{}, err
	}

	var serverIPs []string
	var controllers []mysql.Controller
	var azControllerConns []mysql.AZControllerConnection
	var currentRegion string

	nodeIP := os.Getenv(common.NODE_IP_KEY)
	err = db.Find(&azControllerConns).Error
	if err != nil {
		log.Warningf("query az_controller_connection failed (%s)", err.Error())
		return []string{}, err
	}
	err = db.Where("ip <> ? AND state <> ?", nodeIP, common.CONTROLLER_STATE_EXCEPTION).Find(&controllers).Error
	if err != nil {
		log.Warningf("query controller failed (%s)", err.Error())
		return []string{}, err
	}

	controllerIPToRegion := make(map[string]string)
	for _, conn := range azControllerConns {
		if nodeIP == conn.ControllerIP {
			currentRegion = conn.Region
		}
		controllerIPToRegion[conn.ControllerIP] = conn.Region
	}

	for _, controller := range controllers {
		// skip other region controller
		if region, ok := controllerIPToRegion[controller.IP]; !ok || region != currentRegion {
			continue
		}

		// use pod ip communication in internal region
		serverIP := controller.PodIP
		if serverIP == "" {
			serverIP = controller.IP
		}
		serverIPs = append(serverIPs, serverIP)
	}
	return serverIPs, nil
}

func (g *Genesis) receiveKubernetesData(kChan chan map[int]map[string]KubernetesInfo) {
	for {
		select {
		case k := <-kChan:
			for key, value := range k {
				g.kubernetesData.Store(key, value)
			}
		}
	}
}

func (g *Genesis) GetKubernetesData(orgID int, clusterID string) (KubernetesInfo, bool) {
	k8sDataInterface, ok := g.kubernetesData.Load(orgID)
	if !ok {
		log.Warningf("kubernetes data not found org_id (%d)", orgID)
		return KubernetesInfo{}, false
	}
	k8sData, ok := k8sDataInterface.(map[string]KubernetesInfo)
	if !ok {
		log.Error("kubernetes data interface assert failed")
		return KubernetesInfo{}, false
	}
	k8sInfo, ok := k8sData[clusterID]
	if !ok {
		log.Warningf("kubernetes data not found org_id %d cluster id (%s)", orgID, clusterID)
		return KubernetesInfo{}, false
	}
	return k8sInfo, true
}

func (g *Genesis) GetKubernetesResponse(orgID int, clusterID string) (map[string][]string, error) {
	k8sResp := map[string][]string{}

	k8sInfo, ok := g.GetKubernetesData(orgID, clusterID)

	serverIPs, err := g.getServerIPs(orgID)
	if err != nil {
		return k8sResp, err
	}
	retFlag := false
	for _, serverIP := range serverIPs {
		grpcServer := net.JoinHostPort(serverIP, g.grpcPort)
		conn, err := grpc.Dial(grpcServer, grpc.WithInsecure(), grpc.WithMaxMsgSize(g.grpcMaxMSGLength))
		if err != nil {
			msg := "create grpc connection faild:" + err.Error()
			log.Error(msg)
			return k8sResp, errors.New(msg)
		}
		defer conn.Close()

		client := api.NewControllerClient(conn)
		reqOrgID := uint32(orgID)
		req := &api.GenesisSharingK8SRequest{
			OrgId:     &reqOrgID,
			ClusterId: &clusterID,
		}
		ret, err := client.GenesisSharingK8S(context.Background(), req)
		if err != nil {
			msg := fmt.Sprintf("get (%s) genesis sharing k8s failed (%s) ", serverIP, err.Error())
			log.Error(msg)
			return k8sResp, errors.New(msg)
		}
		entries := ret.GetEntries()
		if len(entries) == 0 {
			log.Debugf("genesis sharing k8s node (%s) entries length is 0", serverIP)
			continue
		}
		epochStr := ret.GetEpoch()
		epoch, err := time.ParseInLocation(common.GO_BIRTHDAY, epochStr, time.Local)
		if err != nil {
			log.Error("genesis api sharing k8s format timestr faild:" + err.Error())
			return k8sResp, err
		}
		if !epoch.After(k8sInfo.Epoch) {
			continue
		}

		retFlag = true
		k8sInfo = KubernetesInfo{
			Epoch:    epoch,
			Entries:  entries,
			ErrorMSG: ret.GetErrorMsg(),
		}
	}
	if !ok && !retFlag {
		return k8sResp, errors.New("no vtap report cluster id:" + clusterID)
	}
	if k8sInfo.ErrorMSG != "" {
		log.Errorf("cluster id (%s) k8s info grpc Error: %s", clusterID, k8sInfo.ErrorMSG)
		return k8sResp, errors.New(k8sInfo.ErrorMSG)
	}
	if len(k8sInfo.Entries) == 0 {
		return k8sResp, errors.New("not found k8s entries")
	}

	g.mutex.Lock()
	g.genesisStatsd.K8SInfoDelay = map[string][]float64{}
	g.genesisStatsd.K8SInfoDelay[clusterID] = []float64{time.Now().Sub(k8sInfo.Epoch).Seconds()}
	statsd.MetaStatsd.RegisterStatsdTable(g)
	g.mutex.Unlock()

	for _, e := range k8sInfo.Entries {
		eType := e.GetType()
		out, err := genesiscommon.ParseCompressedInfo(e.GetCompressedInfo())
		if err != nil {
			log.Warningf("decode decompress error: %s", err.Error())
			return map[string][]string{}, err
		}
		k8sResp[eType] = append(k8sResp[eType], string(out.Bytes()))
	}
	return k8sResp, nil
}

func (g *Genesis) receivePrometheusData(pChan chan map[int]map[string]PrometheusInfo) {
	for {
		select {
		case p := <-pChan:
			for k, v := range p {
				g.prometheusData.Store(k, v)
			}
		}
	}
}

func (g *Genesis) GetPrometheusData(orgID int, clusterID string) (PrometheusInfo, bool) {
	prometheusDataInterface, ok := g.prometheusData.Load(orgID)
	if !ok {
		log.Warningf("prometheus data not found org_id (%d)", orgID)
		return PrometheusInfo{}, false
	}
	prometheusData, ok := prometheusDataInterface.(map[string]PrometheusInfo)
	if !ok {
		log.Error("prometheus data interface assert failed")
		return PrometheusInfo{}, false
	}
	prometheusInfo, ok := prometheusData[clusterID]
	if !ok {
		log.Warningf("prometheus data not found cluster id (%s)", clusterID)
		return PrometheusInfo{}, false
	}
	return prometheusInfo, true
}

func (g *Genesis) GetPrometheusResponse(orgID int, clusterID string) ([]cloudmodel.PrometheusTarget, error) {
	prometheusEntries := []cloudmodel.PrometheusTarget{}

	prometheusInfo, _ := g.GetPrometheusData(orgID, clusterID)

	serverIPs, err := g.getServerIPs(orgID)
	if err != nil {
		return []cloudmodel.PrometheusTarget{}, err
	}
	for _, serverIP := range serverIPs {
		grpcServer := net.JoinHostPort(serverIP, g.grpcPort)
		conn, err := grpc.Dial(grpcServer, grpc.WithInsecure(), grpc.WithMaxMsgSize(g.grpcMaxMSGLength))
		if err != nil {
			msg := "create grpc connection faild:" + err.Error()
			log.Error(msg)
			return []cloudmodel.PrometheusTarget{}, errors.New(msg)
		}
		defer conn.Close()

		client := api.NewControllerClient(conn)
		reqOrgID := uint32(orgID)
		req := &api.GenesisSharingPrometheusRequest{
			OrgId:     &reqOrgID,
			ClusterId: &clusterID,
		}
		ret, err := client.GenesisSharingPrometheus(context.Background(), req)
		if err != nil {
			msg := fmt.Sprintf("get (%s) genesis sharing prometheus failed (%s) ", serverIP, err.Error())
			log.Error(msg)
			return []cloudmodel.PrometheusTarget{}, errors.New(msg)
		}
		entriesByte := ret.GetEntries()
		if entriesByte == nil {
			log.Debugf("genesis sharing prometheus node (%s) entries is nil", serverIP)
			continue
		}
		epochStr := ret.GetEpoch()
		epoch, err := time.ParseInLocation(common.GO_BIRTHDAY, epochStr, time.Local)
		if err != nil {
			log.Error("genesis api sharing prometheus format timestr faild:" + err.Error())
			return []cloudmodel.PrometheusTarget{}, err
		}
		errorMsg := ret.GetErrorMsg()
		if errorMsg != "" {
			log.Warningf("cluster id (%s) prometheus info grpc Error: %s", clusterID, errorMsg)
		}
		if !epoch.After(prometheusInfo.Epoch) {
			continue
		}

		err = json.Unmarshal(entriesByte, &prometheusEntries)
		if err != nil {
			log.Error("genesis api sharing prometheus unmarshal json faild:" + err.Error())
			return []cloudmodel.PrometheusTarget{}, err
		}

		prometheusInfo = PrometheusInfo{
			Epoch:    epoch,
			ErrorMSG: errorMsg,
			Entries:  prometheusEntries,
		}
	}

	if prometheusInfo.ErrorMSG != "" {
		return []cloudmodel.PrometheusTarget{}, errors.New(prometheusInfo.ErrorMSG)
	}

	return prometheusInfo.Entries, nil
}
