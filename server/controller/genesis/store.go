package genesis

import (
	"bytes"
	"compress/zlib"
	"context"
	cloudmodel "server/controller/cloud/model"
	"server/controller/common"
	"server/controller/db/mysql"
	genesiscommon "server/controller/genesis/common"
	"server/controller/genesis/model"
	"sync"
	"time"

	"github.com/deckarep/golang-set"
	uuid "github.com/satori/go.uuid"
	"inet.af/netaddr"
	"server/controller/genesis/config"
)

type VinterfacesStorage struct {
	cfg          config.GenesisConfig
	vCtx         context.Context
	vCancel      context.CancelFunc
	channel      chan PlatformData
	dirty        bool
	mutex        sync.Mutex
	platformInfo PlatformData
}

func NewVinterfacesStorage(cfg config.GenesisConfig, vChan chan PlatformData, ctx context.Context) *VinterfacesStorage {
	vCtx, vCancel := context.WithCancel(ctx)
	return &VinterfacesStorage{
		cfg:          cfg,
		vCtx:         vCtx,
		vCancel:      vCancel,
		channel:      vChan,
		dirty:        false,
		mutex:        sync.Mutex{},
		platformInfo: PlatformData{},
	}
}

func (v *VinterfacesStorage) Renew(data PlatformData) {
	now := time.Now()
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if data.VMs != nil {
		v.platformInfo.VMs.Renew(data.VMs.Fetch(), now)
	}
	if data.VPCs != nil {
		v.platformInfo.VPCs.Renew(data.VPCs.Fetch(), now)
	}
	if data.Hosts != nil {
		v.platformInfo.Hosts.Renew(data.Hosts.Fetch(), now)
	}
	if data.Lldps != nil {
		v.platformInfo.Lldps.Renew(data.Lldps.Fetch(), now)
	}
	if data.Ports != nil {
		v.platformInfo.Ports.Renew(data.Ports.Fetch(), now)
	}
	if data.Networks != nil {
		v.platformInfo.Networks.Renew(data.Networks.Fetch(), now)
	}
	if data.IPlastseens != nil {
		v.platformInfo.IPlastseens.Renew(data.IPlastseens.Fetch(), now)
	}
	if data.Vinterfaces != nil {
		v.platformInfo.Vinterfaces.Renew(data.Vinterfaces.Fetch(), now)
	}
}

func (v *VinterfacesStorage) Update(data PlatformData) {
	now := time.Now()
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if data.VMs != nil {
		v.platformInfo.VMs.Update(data.VMs.Fetch(), now)
	}
	if data.VPCs != nil {
		v.platformInfo.VPCs.Update(data.VPCs.Fetch(), now)
	}
	if data.Hosts != nil {
		v.platformInfo.Hosts.Update(data.Hosts.Fetch(), now)
	}
	if data.Lldps != nil {
		v.platformInfo.Lldps.Update(data.Lldps.Fetch(), now)
	}
	if data.Ports != nil {
		v.platformInfo.Ports.Update(data.Ports.Fetch(), now)
	}
	if data.Networks != nil {
		v.platformInfo.Networks.Update(data.Networks.Fetch(), now)
	}
	if data.IPlastseens != nil {
		v.platformInfo.IPlastseens.Update(data.IPlastseens.Fetch(), now)
	}
	if data.Vinterfaces != nil {
		v.platformInfo.Vinterfaces.Update(data.Vinterfaces.Fetch(), now)
	}
	v.generateIPsAndSubnets()
	v.dirty = true
}

func (v *VinterfacesStorage) generateIPsAndSubnets() {
	v.platformInfo.IPs = []cloudmodel.IP{}
	v.platformInfo.Subnets = []cloudmodel.Subnet{}
	portIDToNetworkID := map[string]string{}
	portIDToVpcID := map[string]string{}
	NetworkIDToVpcID := map[string]string{}
	for _, port := range v.platformInfo.Ports.Fetch() {
		portIDToNetworkID[port.Lcuuid] = port.NetworkLcuuid
		portIDToVpcID[port.Lcuuid] = port.VPCLcuuid
		NetworkIDToVpcID[port.NetworkLcuuid] = port.VPCLcuuid
	}
	// 这里需要根据trident上报的ip信息中last_seen字段进行去重
	// 当ip移到别的接口上时，内存中的ip信息可能会出现同一个ip在两个port上
	// 这时候会保留last_seen比较近的一个port的ip
	validIPs := []model.GenesisIP{}
	vpcIDToIPLastSeens := map[string][]model.GenesisIP{}
	for _, ip := range v.platformInfo.IPlastseens.Fetch() {
		vpcIDToIPLastSeens[portIDToVpcID[ip.Lcuuid]] = append(vpcIDToIPLastSeens[portIDToVpcID[ip.Lcuuid]], ip)
	}
	for _, ips := range vpcIDToIPLastSeens {
		ipToPorts := map[string][]model.GenesisIP{}
		for _, ip := range ips {
			ipToPorts[ip.IP] = append(ipToPorts[ip.IP], ip)
		}
		for _, ipLastSeens := range ipToPorts {
			ipFlag := ipLastSeens[0]
			timeFlag := ipFlag.LastSeen
			for _, ipLastSeen := range ipLastSeens[1:] {
				if ipLastSeen.LastSeen.After(timeFlag) {
					ipFlag = ipLastSeen
					timeFlag = ipLastSeen.LastSeen
				}
			}
			validIPs = append(validIPs, ipFlag)
		}
	}

	networkIDToIPLastSeens := map[string][]model.GenesisIP{}
	for _, ip := range validIPs {
		networkIDToIPLastSeens[portIDToNetworkID[ip.VinterfaceLcuuid]] = append(networkIDToIPLastSeens[portIDToNetworkID[ip.Lcuuid]], ip)
	}

	// 由于目前没获取dhcp信息，所以在这里用一个子网内所有ip计算出一个最小网段
	for networkID, ipLastSeens := range networkIDToIPLastSeens {
		ipsWithMasklen := []model.GenesisIP{}
		ipsWithoutMasklen := []model.GenesisIP{}
		for _, ip := range ipLastSeens {
			if ip.Masklen != 0 {
				ipsWithMasklen = append(ipsWithMasklen, ip)
			} else {
				ipsWithoutMasklen = append(ipsWithoutMasklen, ip)
			}
		}
		knownCIDRs := mapset.NewSet()
		subnetMap := map[string]string{}
		for _, ip := range ipsWithMasklen {
			var cidr netaddr.IPPrefix
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Error(err.Error())
				continue
			}
			if ipNet.Is4() {
				cidr = netaddr.IPPrefixFrom(ipNet, uint8(ip.Masklen))
			} else if ipNet.Is6() {
				cidr = netaddr.IPPrefixFrom(ipNet, uint8(ip.Masklen))
			} else {
				continue
			}
			knownCIDRs.Add(cidr.Masked())
			if _, ok := subnetMap[cidr.Masked().String()]; !ok {
				subnet := cloudmodel.Subnet{
					Lcuuid:        common.GetUUID(networkID+cidr.Masked().String(), uuid.Nil),
					CIDR:          cidr.Masked().String(),
					NetworkLcuuid: networkID,
					VPCLcuuid:     NetworkIDToVpcID[networkID],
				}
				v.platformInfo.Subnets = append(v.platformInfo.Subnets, subnet)
				subnetMap[cidr.Masked().String()] = subnet.Lcuuid
			}
			modelIP := cloudmodel.IP{
				IP:               ip.IP,
				Lcuuid:           ip.Lcuuid,
				SubnetLcuuid:     subnetMap[cidr.Masked().String()],
				VInterfaceLcuuid: ip.VinterfaceLcuuid,
			}
			v.platformInfo.IPs = append(v.platformInfo.IPs, modelIP)
		}

		deducedCIDRs := []netaddr.IPPrefix{}
		prefixV4 := []netaddr.IPPrefix{}
		prefixV6 := []netaddr.IPPrefix{}
		for _, ip := range ipsWithoutMasklen {
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Warning(err.Error())
				continue
			}
			if ipNet.Is4() {
				prefixV4 = append(prefixV4, netaddr.IPPrefixFrom(ipNet, 32))
			} else if ipNet.Is6() {
				prefixV6 = append(prefixV6, netaddr.IPPrefixFrom(ipNet, 128))
			} else {
				log.Warningf("parse ip error: ip is (%s)", ipNet.String())
				continue
			}
		}
		aggreateV4CIDR := genesiscommon.AggregateCIDR(prefixV4, v.cfg.IPv4CIDRMaxMask)
		deducedCIDRs = append(deducedCIDRs, aggreateV4CIDR...)
		aggreateV6CIDR := genesiscommon.AggregateCIDR(prefixV6, v.cfg.IPv6CIDRMaxMask)
		deducedCIDRs = append(deducedCIDRs, aggreateV6CIDR...)
		for _, ip := range ipsWithoutMasklen {
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Warning(err.Error())
				continue
			}
			for _, cidr := range knownCIDRs.ToSlice() {
				if cidr.(netaddr.IPPrefix).Contains(ipNet) {
					modelIP := cloudmodel.IP{
						IP:               ip.IP,
						Lcuuid:           ip.Lcuuid,
						VInterfaceLcuuid: ip.VinterfaceLcuuid,
						SubnetLcuuid:     subnetMap[cidr.(netaddr.IPPrefix).String()],
					}
					v.platformInfo.IPs = append(v.platformInfo.IPs, modelIP)
				}
			}
			for _, cidr := range deducedCIDRs {
				if cidr.Contains(ipNet) {
					if _, ok := subnetMap[cidr.String()]; !ok {
						subnet := cloudmodel.Subnet{
							Lcuuid:        common.GetUUID(networkID+cidr.String(), uuid.Nil),
							NetworkLcuuid: networkID,
							CIDR:          cidr.String(),
							VPCLcuuid:     NetworkIDToVpcID[networkID],
						}
						v.platformInfo.Subnets = append(v.platformInfo.Subnets, subnet)
						subnetMap[cidr.String()] = subnet.Lcuuid
					}
					modelIP := cloudmodel.IP{
						Lcuuid:           ip.Lcuuid,
						IP:               ip.IP,
						VInterfaceLcuuid: ip.VinterfaceLcuuid,
						SubnetLcuuid:     subnetMap[cidr.String()],
					}
					v.platformInfo.IPs = append(v.platformInfo.IPs, modelIP)
				}
			}
		}
	}
}

func (v *VinterfacesStorage) loadFromDatabase() {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	v.platformInfo = PlatformData{}
	var vms []model.GenesisVM
	var vpcs []model.GenesisVpc
	var hosts []model.GenesisHost
	var ports []model.GenesisPort
	var lldps []model.GenesisLldp
	var ipLastSeens []model.GenesisIP
	var networks []model.GenesisNetwork
	var vinterfaces []model.GenesisVinterface

	mysql.Db.Find(&vms)
	v.platformInfo.VMs = NewVMPlatformDataOperation(vms)

	mysql.Db.Find(&vpcs)
	v.platformInfo.VPCs = NewVpcPlatformDataOperation(vpcs)

	mysql.Db.Find(&hosts)
	v.platformInfo.Hosts = NewHostPlatformDataOperation(hosts)

	mysql.Db.Find(&ports)
	v.platformInfo.Ports = NewPortPlatformDataOperation(ports)

	mysql.Db.Find(&lldps)
	v.platformInfo.Lldps = NewLldpInfoPlatformDataOperation(lldps)

	mysql.Db.Find(&ipLastSeens)
	v.platformInfo.IPlastseens = NewIPLastSeenPlatformDataOperation(ipLastSeens)

	mysql.Db.Find(&networks)
	v.platformInfo.Networks = NewNetworkPlatformDataOperation(networks)

	mysql.Db.Find(&vinterfaces)
	v.platformInfo.Vinterfaces = NewVinterfacePlatformDataOperation(vinterfaces)

	v.generateIPsAndSubnets()

	v.channel <- v.platformInfo
}

func (v *VinterfacesStorage) storeToDatabase() {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// 写入新数据前先清空表
	mysql.Db.Exec("DELETE FROM genesis_vm;")
	mysql.Db.Exec("DELETE FROM genesis_ip;")
	mysql.Db.Exec("DELETE FROM genesis_vpc;")
	mysql.Db.Exec("DELETE FROM genesis_host;")
	mysql.Db.Exec("DELETE FROM genesis_port;")
	mysql.Db.Exec("DELETE FROM genesis_lldp;")
	mysql.Db.Exec("DELETE FROM genesis_network;")
	mysql.Db.Exec("DELETE FROM genesis_vinterface;")

	vms := v.platformInfo.VMs.Fetch()
	if len(vms) > 0 {
		mysql.Db.Create(&vms)
	}
	vpcs := v.platformInfo.VPCs.Fetch()
	if len(vpcs) > 0 {
		mysql.Db.Create(&vpcs)
	}
	hosts := v.platformInfo.Hosts.Fetch()
	if len(hosts) > 0 {
		mysql.Db.Create(&hosts)
	}
	ports := v.platformInfo.Ports.Fetch()
	if len(ports) > 0 {
		mysql.Db.Create(&ports)
	}
	lldps := v.platformInfo.Lldps.Fetch()
	if len(lldps) > 0 {
		mysql.Db.Create(&lldps)
	}
	ips := v.platformInfo.IPlastseens.Fetch()
	if len(ips) > 0 {
		mysql.Db.Create(&ips)
	}
	networks := v.platformInfo.Networks.Fetch()
	if len(networks) > 0 {
		mysql.Db.Create(&networks)
	}
	vinterfaces := v.platformInfo.Vinterfaces.Fetch()
	if len(vinterfaces) > 0 {
		mysql.Db.Create(&vinterfaces)
	}
}

func (v *VinterfacesStorage) run() {
	// 启动时先从数据库恢复数据
	v.loadFromDatabase()

	for {
		time.Sleep(time.Duration(v.cfg.DataPersistenceInterval) * time.Second)
		now := time.Now()
		hasChange := false
		v.mutex.Lock()
		ageTime := time.Duration(v.cfg.AgingTime) * time.Second
		hasChange = hasChange || v.platformInfo.VMs.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.VPCs.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.Lldps.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.Ports.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.Networks.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.IPlastseens.Age(now, ageTime)
		hasChange = hasChange || v.platformInfo.Vinterfaces.Age(now, ageTime)
		if hasChange {
			v.generateIPsAndSubnets()
		}
		hasChange = hasChange || v.dirty
		v.dirty = false
		v.mutex.Unlock()
		if hasChange {
			v.storeToDatabase()
		}
		v.channel <- v.platformInfo
	}
}

func (v *VinterfacesStorage) Start() {
	go v.run()
}

func (v *VinterfacesStorage) Stop() {
	if v.vCancel != nil {
		v.vCancel()
	}
}

type KubernetesStorage struct {
	cfg            config.GenesisConfig
	kCtx           context.Context
	kCancel        context.CancelFunc
	channel        chan map[string]KubernetesResponse
	kubernetesData map[string]KubernetesInfo
	mutex          sync.Mutex
}

func NewKubernetesStorage(cfg config.GenesisConfig, kChan chan map[string]KubernetesResponse, ctx context.Context) *KubernetesStorage {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesStorage{
		cfg:            cfg,
		kCtx:           kCtx,
		kCancel:        kCancel,
		channel:        kChan,
		kubernetesData: map[string]KubernetesInfo{},
		mutex:          sync.Mutex{},
	}
}

func (k *KubernetesStorage) Clear() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.kubernetesData = map[string]KubernetesInfo{}
}

func (k *KubernetesStorage) Add(k8sInfo KubernetesInfo) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	kInfo, ok := k.kubernetesData[k8sInfo.ClusterID]
	// trident上报消息中version未变化时，只更新epoch和error_msg
	if ok && kInfo.Version == k8sInfo.Version {
		kInfo.Epoch = time.Now()
		kInfo.ErrorMSG = k8sInfo.ErrorMSG
		k.kubernetesData[k8sInfo.ClusterID] = kInfo
	} else {
		k.kubernetesData[k8sInfo.ClusterID] = k8sInfo
	}
}

func (k *KubernetesStorage) fetch() (map[string]KubernetesResponse, error) {
	kResponses := map[string]KubernetesResponse{}
	for key, v := range k.kubernetesData {
		kResponse := KubernetesResponse{
			ClusterID: key,
			ErrorMSG:  v.ErrorMSG,
			SyncedAt:  v.Epoch,
			Resources: map[string][]string{},
		}
		for _, e := range v.Entries {
			eType := e.GetType()
			eInfo := e.GetCompressedInfo()
			reader := bytes.NewReader(eInfo)
			var out bytes.Buffer
			r, err := zlib.NewReader(reader)
			if err != nil {
				log.Errorf("zlib decompress error: %s", err.Error())
				return map[string]KubernetesResponse{}, err
			}
			out.ReadFrom(r)
			if _, ok := kResponse.Resources[eType]; ok {
				kResponse.Resources[eType] = append(kResponse.Resources[eType], string(out.Bytes()))
			} else {
				kResponse.Resources[eType] = []string{string(out.Bytes())}
			}
		}
		kResponses[key] = kResponse
	}
	return kResponses, nil
}

func (k *KubernetesStorage) run() {
	for {
		time.Sleep(time.Duration(k.cfg.DataPersistenceInterval) * time.Second)
		now := time.Now()
		k.mutex.Lock()
		for key, v := range k.kubernetesData {
			if now.Sub(v.Epoch) <= time.Duration(k.cfg.AgingTime)*time.Second {
				continue
			}
			delete(k.kubernetesData, key)
		}
		k.mutex.Unlock()
		result, err := k.fetch()
		if err == nil {
			k.channel <- result
		}
	}
}

func (k *KubernetesStorage) Start() {
	go k.run()
}

func (k *KubernetesStorage) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}
