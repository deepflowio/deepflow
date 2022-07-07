package genesis

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"net"
	"sync/atomic"

	"github.com/op/go-logging"
	"google.golang.org/grpc"

	"github.com/metaflowys/metaflow/message/trident"
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/genesis/config"
	"github.com/metaflowys/metaflow/server/controller/model"
	"github.com/metaflowys/metaflow/server/libs/queue"
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

func (g *Genesis) GetIPsData() []cloudmodel.IP {
	return g.ips.Load().([]cloudmodel.IP)
}

func (g *Genesis) GetSubnetsData() []cloudmodel.Subnet {
	return g.subnets.Load().([]cloudmodel.Subnet)
}

func (g *Genesis) GetVMsData() []model.GenesisVM {
	return g.vms.Load().([]model.GenesisVM)
}

func (g *Genesis) GetVPCsData() []model.GenesisVpc {
	return g.vpcs.Load().([]model.GenesisVpc)
}

func (g *Genesis) GetHostsData() []model.GenesisHost {
	return g.hosts.Load().([]model.GenesisHost)
}

func (g *Genesis) GetLldpsData() []model.GenesisLldp {
	return g.lldps.Load().([]model.GenesisLldp)
}

func (g *Genesis) GetPortsData() []model.GenesisPort {
	return g.ports.Load().([]model.GenesisPort)
}

func (g *Genesis) GetNetworksData() []model.GenesisNetwork {
	return g.networks.Load().([]model.GenesisNetwork)
}

func (g *Genesis) GetVinterfacesData() []model.GenesisVinterface {
	return g.vinterfaces.Load().([]model.GenesisVinterface)
}

func (g *Genesis) GetIPLastSeensData() []model.GenesisIP {
	return g.iplastseens.Load().([]model.GenesisIP)
}

func (g *Genesis) GetKubernetesData() map[string]KubernetesInfo {
	return g.kubernetesData.Load().(map[string]KubernetesInfo)
}

func (g *Genesis) GetKubernetesResponse(clusterID string) (map[string][]string, error) {
	k8sResp := map[string][]string{}

	localK8sDatas := g.GetKubernetesData()
	k8sInfo, ok := localK8sDatas[clusterID]
	if !ok {
		var controllers []mysql.Controller
		mysql.Db.Find(&controllers)
		retFlag := false
		for _, controller := range controllers {
			// FIXME: read from config file
			grpcServer := net.JoinHostPort(controller.IP, "20035")
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
				log.Error("request grpc api faild:" + err.Error())
				continue
			} else {
				retFlag = true
				entries := ret.GetEntries()
				errorMsg := ret.GetErrorMsg()
				if errorMsg != "" {
					log.Warningf("cluster id (%s) Error: %s", clusterID, errorMsg)
				}
				k8sInfo = KubernetesInfo{
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
