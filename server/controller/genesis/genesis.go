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
	"bytes"
	"compress/zlib"
	"context"
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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
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
	cfg              gconfig.GenesisConfig
	genesisSyncData  atomic.Value
	kubernetesData   atomic.Value
	genesisStatsd    statsd.GenesisStatsd
}

func NewGenesis(cfg *config.ControllerConfig) *Genesis {
	var sData atomic.Value
	sData.Store(GenesisSyncData{})
	var kData atomic.Value
	kData.Store(map[string]KubernetesInfo{})
	GenesisService = &Genesis{
		mutex:            sync.RWMutex{},
		grpcPort:         cfg.GrpcPort,
		grpcMaxMSGLength: cfg.GrpcMaxMessageLength,
		cfg:              cfg.GenesisCfg,
		genesisSyncData:  sData,
		kubernetesData:   kData,
		genesisStatsd: statsd.GenesisStatsd{
			K8SInfoDelay: make(map[string][]int),
		},
	}
	return GenesisService
}

func (g *Genesis) Start() {
	ctx := context.Context(context.Background())
	genesisSyncDataChan := make(chan GenesisSyncData)
	kubernetesDataChan := make(chan map[string]KubernetesInfo)
	sQueue := queue.NewOverwriteQueue("genesis sync data", g.cfg.QueueLengths)
	kQueue := queue.NewOverwriteQueue("genesis k8s data", g.cfg.QueueLengths)

	// 由于可能需要从数据库恢复数据，这里先启动监听
	go g.receiveGenesisSyncData(genesisSyncDataChan)
	go g.receiveKubernetesData(kubernetesDataChan)

	go func() {
		Synchronizer = NewGenesisSynchronizerServer(g.cfg, sQueue, kQueue)

		vStorage := NewSyncStorage(g.cfg, genesisSyncDataChan, ctx)
		vStorage.Start()
		vUpdater := NewGenesisSyncRpcUpdater(vStorage, sQueue, g.cfg, ctx)
		vUpdater.Start()

		kStorage := NewKubernetesStorage(g.cfg, kubernetesDataChan, ctx)
		kStorage.Start()
		kUpdater := NewKubernetesRpcUpdater(kStorage, kQueue, ctx)
		kUpdater.Start()
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

func (g *Genesis) GetGenesisSyncData() GenesisSyncData {
	return g.genesisSyncData.Load().(GenesisSyncData)
}

func (g *Genesis) GetGenesisSyncResponse() (GenesisSyncData, error) {
	retGenesisSyncData := GenesisSyncData{}

	var controllers []mysql.Controller
	var azControllerConns []mysql.AZControllerConnection
	var currentRegion string

	mysql.Db.Where("state <> ?", common.CONTROLLER_STATE_EXCEPTION).Find(&controllers)
	mysql.Db.Find(&azControllerConns)

	controllerIPToRegion := make(map[string]string)
	for _, conn := range azControllerConns {
		if os.Getenv(common.NODE_IP_KEY) == conn.ControllerIP {
			currentRegion = conn.Region
		}
		controllerIPToRegion[conn.ControllerIP] = conn.Region
	}

	syncIPLcuuidSet := map[string]bool{}
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
		mysql.Db.Where("node_ip = ?", controller.IP).Find(&storages)
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
		ret, err := client.GenesisSharingSync(context.Background(), &api.GenesisSharingSyncRequest{})
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
				Name:                v.GetName(),
				IPs:                 v.GetIps(),
				Mac:                 v.GetMac(),
				TapName:             v.GetTapName(),
				TapMac:              v.GetTapMac(),
				DeviceLcuuid:        v.GetDeviceLcuuid(),
				DeviceName:          v.GetDeviceName(),
				DeviceType:          v.GetDeviceType(),
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
				Name:        p.GetName(),
				ProcessName: p.GetProcessName(),
				CMDLine:     p.GetCmdLine(),
				User:        p.GetUser(),
				OSAPPTags:   p.GetOsAppTags(),
				NodeIP:      p.GetNodeIp(),
				StartTime:   pStartTime,
			})
		}
	}
	return retGenesisSyncData, nil
}

func (g *Genesis) receiveKubernetesData(kChan chan map[string]KubernetesInfo) {
	for {
		select {
		case k := <-kChan:
			g.kubernetesData.Store(k)
		}
	}
}

func (g *Genesis) GetKubernetesData() map[string]KubernetesInfo {
	return g.kubernetesData.Load().(map[string]KubernetesInfo)
}

func (g *Genesis) GetKubernetesResponse(clusterID string) (map[string][]string, error) {
	k8sResp := map[string][]string{}

	localK8sDatas := g.GetKubernetesData()
	k8sInfo, ok := localK8sDatas[clusterID]

	var controllers []mysql.Controller
	var azControllerConns []mysql.AZControllerConnection
	var currentRegion string

	nodeIP := os.Getenv(common.NODE_IP_KEY)
	mysql.Db.Find(&azControllerConns)
	mysql.Db.Where("ip <> ? AND state <> ?", nodeIP, common.CONTROLLER_STATE_EXCEPTION).Find(&controllers)

	controllerIPToRegion := make(map[string]string)
	for _, conn := range azControllerConns {
		if nodeIP == conn.ControllerIP {
			currentRegion = conn.Region
		}
		controllerIPToRegion[conn.ControllerIP] = conn.Region
	}

	retFlag := false
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
		grpcServer := net.JoinHostPort(serverIP, g.grpcPort)
		conn, err := grpc.Dial(grpcServer, grpc.WithInsecure(), grpc.WithMaxMsgSize(g.grpcMaxMSGLength))
		if err != nil {
			msg := "create grpc connection faild:" + err.Error()
			log.Error(msg)
			return k8sResp, errors.New(msg)
		}
		defer conn.Close()

		client := api.NewControllerClient(conn)
		req := &api.GenesisSharingK8SRequest{
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
		return k8sResp, errors.New("no vtap k8s report cluster id:" + clusterID)
	}
	if k8sInfo.ErrorMSG != "" {
		log.Errorf("cluster id (%s) k8s info grpc Error: %s", clusterID, k8sInfo.ErrorMSG)
		return k8sResp, errors.New(k8sInfo.ErrorMSG)
	}

	g.mutex.Lock()
	g.genesisStatsd.K8SInfoDelay = map[string][]int{}
	g.genesisStatsd.K8SInfoDelay[clusterID] = []int{int(time.Now().Sub(k8sInfo.Epoch).Seconds())}
	statsd.MetaStatsd.RegisterStatsdTable(g)
	g.mutex.Unlock()

	for _, e := range k8sInfo.Entries {
		eType := e.GetType()
		eInfo := e.GetCompressedInfo()
		reader := bytes.NewReader(eInfo)
		var out bytes.Buffer
		r, err := zlib.NewReader(reader)
		if err != nil {
			log.Errorf("zlib decompress error: %s", err.Error())
			return k8sResp, err
		}
		out.ReadFrom(r)
		if _, ok := k8sResp[eType]; ok {
			k8sResp[eType] = append(k8sResp[eType], string(out.Bytes()))
		} else {
			k8sResp[eType] = []string{string(out.Bytes())}
		}
	}
	return k8sResp, nil
}
