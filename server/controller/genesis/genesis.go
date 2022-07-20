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
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/op/go-logging"
	"google.golang.org/grpc"

	"github.com/deepflowys/deepflow/message/trident"
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/genesis/config"
	"github.com/deepflowys/deepflow/server/controller/model"
	"github.com/deepflowys/deepflow/server/controller/statsd"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("genesis")
var GenesisService *Genesis
var Synchronizer *SynchronizerServer

type Genesis struct {
	cfg            config.GenesisConfig
	ips            atomic.Value
	subnets        atomic.Value
	vms            atomic.Value
	vpcs           atomic.Value
	hosts          atomic.Value
	lldps          atomic.Value
	ports          atomic.Value
	networks       atomic.Value
	vinterfaces    atomic.Value
	iplastseens    atomic.Value
	kubernetesData atomic.Value
	genesisStatsd  statsd.GenesisStatsd
}

func NewGenesis(cfg config.GenesisConfig) *Genesis {
	var ipData atomic.Value
	ipData.Store([]cloudmodel.IP{})
	var subnetData atomic.Value
	subnetData.Store([]cloudmodel.Subnet{})
	var vmData atomic.Value
	vmData.Store([]model.GenesisVM{})
	var vpcData atomic.Value
	vpcData.Store([]model.GenesisVpc{})
	var hostData atomic.Value
	hostData.Store([]model.GenesisHost{})
	var lldpData atomic.Value
	lldpData.Store([]model.GenesisLldp{})
	var portData atomic.Value
	portData.Store([]model.GenesisPort{})
	var networkData atomic.Value
	networkData.Store([]model.GenesisNetwork{})
	var vData atomic.Value
	vData.Store([]model.GenesisVinterface{})
	var lData atomic.Value
	lData.Store([]model.GenesisIP{})
	var kData atomic.Value
	kData.Store(map[string]KubernetesInfo{})
	GenesisService = &Genesis{
		cfg:            cfg,
		ips:            ipData,
		subnets:        subnetData,
		vms:            vmData,
		vpcs:           vpcData,
		hosts:          hostData,
		lldps:          lldpData,
		ports:          portData,
		networks:       networkData,
		vinterfaces:    vData,
		iplastseens:    lData,
		kubernetesData: kData,
		genesisStatsd: statsd.GenesisStatsd{
			K8SInfoDelay: make(map[string][]int),
		},
	}
	return GenesisService
}

// 迁移genesis
// 功能梳理：
//   1.获取trident上报的数据，进行解析，目前先解析原来vinterface和kubernetes-info接口的内容供cloud使用
//     - trisolaris已经启动了与采集器通信的grpc server，故通过该server获取数据
//   2.由于进度问题暂时无法取消原有的genesis模块，trident的信息还需要通过grpc service提供给原来的genesis模块
//   3.数据的重载和持久化，通过mysql对数据进行持久化，以及进程重启后的数据恢复

func (g *Genesis) Start() {
	ctx := context.Context(context.Background())
	platformDataChan := make(chan PlatformData)
	kubernetesDataChan := make(chan map[string]KubernetesInfo)
	vQueue := queue.NewOverwriteQueue("genesis platfrom data", g.cfg.QueueLengths)
	kQueue := queue.NewOverwriteQueue("genesis kubernetes info", g.cfg.QueueLengths)

	// 由于可能需要从数据库恢复数据，这里先启动监听
	go g.receivePlatformData(platformDataChan)
	go g.receiveKubernetesData(kubernetesDataChan)

	go func() {
		Synchronizer = NewGenesisSynchronizerServer(g.cfg, vQueue, kQueue)

		vStorage := NewVinterfacesStorage(g.cfg, platformDataChan, ctx)
		vStorage.Start()
		vUpdater := NewVinterfacesRpcUpdater(vStorage, vQueue, g.cfg.LocalIPRanges, g.cfg.ExcludeIPRanges, ctx)
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

func (g *Genesis) receivePlatformData(pChan chan PlatformData) {
	for {
		select {
		case p := <-pChan:
			g.ips.Store(p.IPs)
			g.subnets.Store(p.Subnets)
			g.vms.Store(p.VMs.Fetch())
			g.vpcs.Store(p.VPCs.Fetch())
			g.hosts.Store(p.Hosts.Fetch())
			g.lldps.Store(p.Lldps.Fetch())
			g.ports.Store(p.Ports.Fetch())
			g.networks.Store(p.Networks.Fetch())
			g.vinterfaces.Store(p.Vinterfaces.Fetch())
			g.iplastseens.Store(p.IPlastseens.Fetch())
		}
	}
}

func (g *Genesis) receiveKubernetesData(kChan chan map[string]KubernetesInfo) {
	for {
		select {
		case k := <-kChan:
			g.kubernetesData.Store(k)
		}
	}
}

func (g *Genesis) GetIPsData(isLocal bool) []cloudmodel.IP {
	return g.ips.Load().([]cloudmodel.IP)
}

func (g *Genesis) GetSubnetsData(isLocal bool) []cloudmodel.Subnet {
	return g.subnets.Load().([]cloudmodel.Subnet)
}

func (g *Genesis) GetVMsData(isLocal bool) []model.GenesisVM {
	if isLocal {
		return g.vms.Load().([]model.GenesisVM)
	} else {
		var vms []model.GenesisVM
		mysql.Db.Find(&vms)
		return vms
	}
}

func (g *Genesis) GetVPCsData(isLocal bool) []model.GenesisVpc {
	if isLocal {
		return g.vpcs.Load().([]model.GenesisVpc)
	} else {
		var vpcs []model.GenesisVpc
		mysql.Db.Find(&vpcs)
		return vpcs
	}
}

func (g *Genesis) GetHostsData(isLocal bool) []model.GenesisHost {
	if isLocal {
		return g.hosts.Load().([]model.GenesisHost)
	} else {
		var hosts []model.GenesisHost
		mysql.Db.Find(&hosts)
		return hosts
	}
}

func (g *Genesis) GetLldpsData(isLocal bool) []model.GenesisLldp {
	if isLocal {
		return g.lldps.Load().([]model.GenesisLldp)
	} else {
		var lldps []model.GenesisLldp
		mysql.Db.Find(&lldps)
		return lldps
	}
}

func (g *Genesis) GetPortsData(isLocal bool) []model.GenesisPort {
	if isLocal {
		return g.ports.Load().([]model.GenesisPort)
	} else {
		var ports []model.GenesisPort
		mysql.Db.Find(&ports)
		return ports
	}
}

func (g *Genesis) GetNetworksData(isLocal bool) []model.GenesisNetwork {
	if isLocal {
		return g.networks.Load().([]model.GenesisNetwork)
	} else {
		var networks []model.GenesisNetwork
		mysql.Db.Find(&networks)
		return networks
	}
}

func (g *Genesis) GetVinterfacesData(isLocal bool) []model.GenesisVinterface {
	if isLocal {
		return g.vinterfaces.Load().([]model.GenesisVinterface)
	} else {
		var vinterfaces []model.GenesisVinterface
		mysql.Db.Find(&vinterfaces)
		return vinterfaces
	}
}

func (g *Genesis) GetIPLastSeensData(isLocal bool) []model.GenesisIP {
	if isLocal {
		return g.iplastseens.Load().([]model.GenesisIP)
	} else {
		var ips []model.GenesisIP
		mysql.Db.Find(&ips)
		return ips
	}
}

func (g *Genesis) GetKubernetesData() map[string]KubernetesInfo {
	return g.kubernetesData.Load().(map[string]KubernetesInfo)
}

func (g *Genesis) GetKubernetesResponse(clusterID string) (map[string][]string, error) {
	k8sResp := map[string][]string{}
	g.genesisStatsd.K8SInfoDelay = map[string][]int{}

	localK8sDatas := g.GetKubernetesData()
	k8sInfo, ok := localK8sDatas[clusterID]
	if !ok {
		var controllers []mysql.Controller
		mysql.Db.Find(&controllers)
		retFlag := false
		for _, controller := range controllers {
			grpcServer := net.JoinHostPort(controller.IP, g.cfg.GRPCServerPort)
			conn, err := grpc.Dial(grpcServer, grpc.WithInsecure())
			if err != nil {
				log.Error("create grpc connection faild:" + err.Error())
				continue
			}
			defer conn.Close()

			client := trident.NewSynchronizerClient(conn)
			req := trident.GenesisSharingK8SRequest{
				ClusterId: &clusterID,
			}
			ret, err := client.GenesisSharingK8S(context.Background(), &req)
			if err != nil {
				log.Warning(err.Error())
				continue
			} else {
				retFlag = true
				epochStr := ret.GetEpoch()
				epoch, err := time.ParseInLocation(common.GO_BIRTHDAY, epochStr, time.Local)
				if err != nil {
					log.Error("genesis api sharing k8s format timestr faild:" + err.Error())
					return k8sResp, err
				}
				entries := ret.GetEntries()
				errorMsg := ret.GetErrorMsg()
				if errorMsg != "" {
					log.Warningf("cluster id (%s) Error: %s", clusterID, errorMsg)
				}
				k8sInfo = KubernetesInfo{
					Epoch:    epoch,
					Entries:  entries,
					ErrorMSG: errorMsg,
				}
				break
			}
		}
		if !retFlag {
			return k8sResp, errors.New("no vtap report cluster id:" + clusterID)
		}
	}

	g.genesisStatsd.K8SInfoDelay[clusterID] = []int{int(time.Now().Sub(k8sInfo.Epoch).Seconds())}

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
	statsd.MetaStatsd.RegisterStatsdTable(g)
	return k8sResp, nil
}
