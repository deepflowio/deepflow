package genesis

import (
	"context"
	"fmt"
	tridentcommon "gitlab.yunshan.net/yunshan/metaflow/message/common"
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"
	"inet.af/netaddr"
	"server/controller/common"
	genesiscommon "server/controller/genesis/common"
	"server/controller/genesis/model"
	genesismodel "server/controller/genesis/model"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"gitlab.yunshan.net/yunshan/metaflow/libs/queue"
)

type VinterfacesRpcUpdater struct {
	vCtx               context.Context
	vCancel            context.CancelFunc
	storage            *VinterfacesStorage
	outputQueue        queue.QueueReader
	localIPRanges      []netaddr.IPPrefix
	excludeIPRanges    []netaddr.IPPrefix
	platformDataByPeer map[uint32]PlatformData
}

func NewVinterfacesRpcUpdater(storage *VinterfacesStorage, queue queue.QueueReader, localIPString, excludeIPString []string, ctx context.Context) *VinterfacesRpcUpdater {
	localIPRanges := []netaddr.IPPrefix{}
	if len(localIPString) > 0 {
		for _, l := range localIPString {
			localIPRange, err := netaddr.ParseIPPrefix(l)
			if err != nil {
				localIPRangeSlice, err := netaddr.ParseIPRange(l)
				if err != nil {
					log.Error("parse local ip ranges error: " + err.Error())
					continue
				}
				localIPRanges = append(localIPRanges, localIPRangeSlice.Prefixes()...)
			} else {
				localIPRanges = append(localIPRanges, localIPRange)
			}
		}
	}

	excludeIPRanges := []netaddr.IPPrefix{}
	if len(excludeIPString) > 0 {
		for _, e := range excludeIPString {
			excludeIPRange, err := netaddr.ParseIPPrefix(e)
			if err != nil {
				excludeIPRangeSlice, err := netaddr.ParseIPRange(e)
				if err != nil {
					log.Error("parse exclude ip ranges error: " + err.Error())
				}
				excludeIPRanges = append(excludeIPRanges, excludeIPRangeSlice.Prefixes()...)
			} else {
				excludeIPRanges = append(excludeIPRanges, excludeIPRange)
			}
		}
	}

	vCtx, vCancel := context.WithCancel(ctx)
	return &VinterfacesRpcUpdater{
		vCtx:               vCtx,
		vCancel:            vCancel,
		storage:            storage,
		outputQueue:        queue,
		localIPRanges:      localIPRanges,
		excludeIPRanges:    excludeIPRanges,
		platformDataByPeer: map[uint32]PlatformData{},
	}
}

func (v *VinterfacesRpcUpdater) ParseVinterfaceInfo(info *trident.GenesisPlatformData, peer string, vtapID int, k8sClusterID, deviceType string) []genesismodel.GenesisVinterface {
	var isContainer bool
	if deviceType == genesiscommon.DEVICE_TYPE_DOCKER_HOST {
		isContainer = true
	}
	epoch := time.Now()
	VIFs := []genesismodel.GenesisVinterface{}
	parsedGlobalIPs, err := genesiscommon.ParseIPOutput(info.GetRawIpAddrs()[0])
	if err != nil {
		log.Errorf("parse ip output error: (%s)", err)
		return VIFs
	}
	ifIDToInterface := map[uint32]genesiscommon.Iface{}
	ifNameToInterface := map[string]genesiscommon.Iface{}
	for _, item := range parsedGlobalIPs {
		if item.Name == "lo" {
			continue
		}
		if item.MAC == "" {
			continue
		}
		ifIDToInterface[uint32(item.Index)] = item
		ifNameToInterface[item.Name] = item
		vIF := genesismodel.GenesisVinterface{
			Name:    item.Name,
			Mac:     item.MAC,
			TapName: item.Name,
			TapMac:  item.MAC,
		}
		// ignore interfaces without ip for container nodes
		// but keep these for kvm hosts
		if isContainer && len(item.IPs) == 0 {
			continue
		}
		ipSlice := []string{}
		for _, ip := range item.IPs {
			if ip.Address == "" || ip.MaskLen == 0 {
				continue
			}
			ipSlice = append(ipSlice, fmt.Sprintf("%s/%v", ip.Address, ip.MaskLen))
		}
		vIF.IPs = strings.Join(ipSlice, ",")
		vIF.Lcuuid = common.GetUUID(vIF.Name+vIF.Mac+strconv.Itoa(vtapID), uuid.Nil)
		vIF.DeviceLcuuid = common.GetUUID(vIF.Name+vIF.Mac+strconv.Itoa(vtapID), uuid.Nil)
		vIF.DeviceType = deviceType
		vIF.HostIP = peer
		vIF.LastSeen = epoch
		vIF.VtapID = vtapID
		vIF.KubernetesClusterID = k8sClusterID
		VIFs = append(VIFs, vIF)
	}
	deviceIDToMinMAC := map[string]uint64{}
	for _, iface := range info.Interfaces {
		ifaceMAC := iface.GetMac()
		ifaceDeviceID := iface.GetDeviceId()
		if iMac, ok := deviceIDToMinMAC[ifaceDeviceID]; ok {
			if ifaceMAC < iMac {
				deviceIDToMinMAC[ifaceDeviceID] = ifaceMAC
			}
		} else {
			deviceIDToMinMAC[ifaceDeviceID] = ifaceMAC
		}
	}
	deviceIDToUUID := map[string]string{}
	for key, value := range deviceIDToMinMAC {
		deviceIDToUUID[key] = common.GetUUID(key+fmt.Sprintf("%d", value), uuid.Nil)
	}
	for _, iface := range info.Interfaces {
		vIF := genesismodel.GenesisVinterface{
			Name: iface.GetName(),
			Mac:  genesiscommon.Uint64ToMac(iface.GetMac()).String(),
		}
		hasNetMask := false
		for _, addr := range iface.Ip {
			hasNetMask = strings.Contains(addr, `/`)
			sIP := strings.Split(addr, `/`)[0]
			netIP, err := netaddr.ParseIP(sIP)
			if err != nil {
				log.Errorf(err.Error())
				return VIFs
			}
			excludeFlag := false
			for _, ipRange := range v.excludeIPRanges {
				if ipRange.Contains(netIP) {
					excludeFlag = true
					break
				}
			}
			if excludeFlag {
				continue
			}
			if vIF.IPs == "" {
				vIF.IPs = netIP.String()
			} else {
				vIF.IPs += ("," + netIP.String())
			}
		}
		vIF.Lcuuid = common.GetUUID(vIF.Name+vIF.Mac+vIF.IPs+strconv.Itoa(vtapID), uuid.Nil)
		if gIF, ok := ifIDToInterface[iface.GetTapIndex()]; ok && isContainer {
			vIF.TapName = gIF.Name
			vIF.TapMac = gIF.MAC
		} else if gIF, ok := ifNameToInterface[iface.GetName()]; ok && !isContainer {
			vIF.TapName = gIF.Name
			vIF.TapMac = gIF.MAC
		}
		if isContainer {
			if hasNetMask {
				// 拿不到子网的时候不填写该uuid
				vIF.DeviceLcuuid = deviceIDToUUID[iface.GetDeviceId()]
			}
			vIF.DeviceName = fmt.Sprintf("namespace-%s", iface.GetDeviceId())
			vIF.DeviceType = genesiscommon.DEVICE_TYPE_DOCKER_CONTAINER
		} else if deviceType == genesiscommon.DEVICE_TYPE_KVM_HOST {
			vIF.DeviceLcuuid = iface.GetDeviceId()
			vIF.DeviceName = iface.GetDeviceName()
			vIF.DeviceType = genesiscommon.DEVICE_TYPE_KVM_VM
		} else {
			// 忽略workload类型
			continue
		}
		vIF.HostIP = peer
		vIF.LastSeen = epoch
		vIF.VtapID = vtapID
		vIF.KubernetesClusterID = k8sClusterID
		VIFs = append(VIFs, vIF)
	}
	return VIFs
}

func (v *VinterfacesRpcUpdater) ParseHostAsVmPlatformInfo(info *trident.GenesisPlatformData, peer, natIP string, vtapID int) PlatformData {
	hostName := strings.Trim(info.GetRawHostname(), " \n")
	interfaces, err := genesiscommon.ParseIPOutput(strings.Trim(info.GetRawIpAddrs()[0], " "))
	if err != nil {
		log.Error(err.Error())
		return PlatformData{}
	}
	// check if vm is behind NAT
	behindNat := peer != natIP
	vpc := model.GenesisVpc{
		Name:   "default-public-cloud-vpc",
		Lcuuid: common.GetUUID("default-public-cloud-vpc", uuid.Nil),
	}
	if behindNat {
		vpc = model.GenesisVpc{
			Name:   "VPC-" + peer,
			Lcuuid: common.GetUUID("VPC-"+peer, uuid.Nil),
		}
	}
	vpcs := []model.GenesisVpc{vpc}

	vm := model.GenesisVM{
		Name:         hostName,
		Label:        hostName,
		Lcuuid:       common.GetUUID(hostName, uuid.Nil),
		VPCLcuuid:    vpc.Lcuuid,
		LaunchServer: "127.0.0.1",
		State:        common.VM_STATE_RUNNING,
		CreatedAt:    time.Now(),
	}
	vms := []model.GenesisVM{vm}

	nameToNetwork := map[string]model.GenesisNetwork{}
	ports := []model.GenesisPort{}
	ipLastSeens := []model.GenesisIP{}
	for _, iface := range interfaces {
		if iface.MAC == "" {
			continue
		}
		ips := iface.IPs
		firstIP := genesiscommon.VifInfo{}
		ipFlag := false
		for _, sIP := range ips {
			if sIP.Scope == "global" {
				firstIP = sIP
				ipFlag = true
				break
			}
		}
		if !ipFlag {
			continue
		}
		isExternal := false
		for _, i := range ips {
			pIP, err := netaddr.ParseIP(i.Address)
			if err != nil {
				log.Error(err.Error())
				return PlatformData{}
			}

			localFlag := false
			for _, ipRange := range v.localIPRanges {
				if ipRange.Contains(pIP) {
					localFlag = true
					break
				}
			}
			if !localFlag {
				isExternal = true
				break
			}
		}
		networkName := fmt.Sprintf("Network-%s/%v", firstIP.Address, firstIP.MaskLen)
		network, ok := nameToNetwork[networkName]
		vType := common.VIF_TYPE_LAN
		netType := common.NETWORK_TYPE_LAN
		if isExternal {
			vType = common.VIF_TYPE_WAN
			netType = common.NETWORK_TYPE_WAN
		}
		if !ok {
			network = model.GenesisNetwork{
				Lcuuid:         common.GetUUID(networkName, uuid.Nil),
				Name:           networkName,
				SegmentationID: 1,
				VPCLcuuid:      vpc.Lcuuid,
				External:       isExternal,
				NetType:        netType,
			}
			nameToNetwork[networkName] = network
		}
		port := model.GenesisPort{
			Lcuuid:        common.GetUUID(hostName+iface.MAC, uuid.Nil),
			Type:          vType,
			Mac:           iface.MAC,
			DeviceLcuuid:  vm.Lcuuid,
			NetworkLcuuid: network.Lcuuid,
			VPCLcuuid:     vm.VPCLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_VM,
		}
		ports = append(ports, port)
		for _, p := range ips {
			// ignore lin scope
			if p.Scope != "global" && p.Scope != "host" {
				continue
			}
			oIP, err := netaddr.ParseIP(p.Address)
			if err != nil {
				log.Warning(err.Error())
				continue
			}
			ipLastSeen := model.GenesisIP{
				Lcuuid:           common.GetUUID(hostName+oIP.String()+port.Lcuuid, uuid.Nil),
				VinterfaceLcuuid: port.Lcuuid,
				IP:               p.Address,
				Masklen:          p.MaskLen,
				LastSeen:         time.Now(),
			}
			ipLastSeens = append(ipLastSeens, ipLastSeen)
		}
	}
	networks := []model.GenesisNetwork{}
	for _, n := range nameToNetwork {
		networks = append(networks, n)
	}
	return PlatformData{
		VMs:         NewVMPlatformDataOperation(vms),
		VPCs:        NewVpcPlatformDataOperation(vpcs),
		Ports:       NewPortPlatformDataOperation(ports),
		Networks:    NewNetworkPlatformDataOperation(networks),
		IPlastseens: NewIPLastSeenPlatformDataOperation(ipLastSeens),
	}
}

func (v *VinterfacesRpcUpdater) UnmarshalProtobuf(info *trident.GenesisPlatformData, peer string, vtapID int, k8sClusterID string) PlatformData {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_KVM_HOST)
	platformData := PlatformData{}
	platformData.Vinterfaces = NewVinterfacePlatformDataOperation(vifs)

	return platformData
}

func (v *VinterfacesRpcUpdater) UnmarshalKubernetesProtobuf(info *trident.GenesisPlatformData, peer, natIP string, vtapID int, k8sClusterID string) PlatformData {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_DOCKER_HOST)
	platformData := PlatformData{}
	vinterfaces := NewVinterfacePlatformDataOperation(vifs)
	if info.GetPlatformEnabled() {
		platformData = v.ParseHostAsVmPlatformInfo(info, peer, natIP, vtapID)
	}
	platformData.Vinterfaces = vinterfaces

	return platformData
}

func (v *VinterfacesRpcUpdater) UnmarshalWorkloadProtobuf(info *trident.GenesisPlatformData, peer, natIP string, vtapID int, k8sClusterID, tridentType string) PlatformData {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, tridentType)
	platformData := PlatformData{}
	vinterfaces := NewVinterfacePlatformDataOperation(vifs)
	if info.GetPlatformEnabled() {
		platformData = v.ParseHostAsVmPlatformInfo(info, peer, natIP, vtapID)
	}
	platformData.Vinterfaces = vinterfaces

	return platformData
}

func (v *VinterfacesRpcUpdater) run() {
	for {
		platformData := PlatformData{}
		info := v.outputQueue.Get().(VIFRPCMessage)
		if info.msgType == genesiscommon.TYPE_EXIT {
			break
		}
		log.Debugf("from (%s) vtap_id (%v) type (%v) received (%s)", info.peer, info.vtapID, info.msgType, info.message)
		if info.msgType == genesiscommon.TYPE_RENEW {
			if info.vtapID != 0 {
				peerInfo, ok := v.platformDataByPeer[info.vtapID]
				if ok {
					v.storage.Renew(peerInfo)
				}
			}
		} else if info.msgType == genesiscommon.TYPE_UPDATE {
			infoData := info.message.GetPlatformData()
			tridentType := info.message.GetTridentType()
			natIP := info.message.GetNatIp()
			k8sClusterID := info.message.GetKubernetesClusterId()
			if tridentType == tridentcommon.TridentType_TT_PHYSICAL_MACHINE {
				platformData = v.UnmarshalWorkloadProtobuf(infoData, info.peer, natIP, int(info.vtapID), k8sClusterID, genesiscommon.DEVICE_TYPE_PHYSICAL_MACHINE)
			} else if tridentType == tridentcommon.TridentType_TT_PUBLIC_CLOUD {
				platformData = v.UnmarshalWorkloadProtobuf(infoData, info.peer, natIP, int(info.vtapID), k8sClusterID, genesiscommon.DEVICE_TYPE_PUBLIC_CLOUD)
			} else if tridentType == tridentcommon.TridentType_TT_HOST_POD || tridentType == tridentcommon.TridentType_TT_VM_POD {
				platformData = v.UnmarshalKubernetesProtobuf(infoData, info.peer, natIP, int(info.vtapID), k8sClusterID)
			} else {
				platformData = v.UnmarshalProtobuf(infoData, info.peer, int(info.vtapID), k8sClusterID)
			}
			if info.vtapID != 0 {
				v.platformDataByPeer[info.vtapID] = platformData
			}
			v.storage.Update(platformData)
		}
	}
}

func (v *VinterfacesRpcUpdater) Start() {
	go v.run()
}

func (v *VinterfacesRpcUpdater) Stop() {
	if v.vCancel != nil {
		v.vCancel()
	}
}

type KubernetesRpcUpdater struct {
	kCtx        context.Context
	kCancel     context.CancelFunc
	storage     *KubernetesStorage
	outputQueue queue.QueueReader
}

func NewKubernetesRpcUpdater(storage *KubernetesStorage, queue queue.QueueReader, ctx context.Context) *KubernetesRpcUpdater {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesRpcUpdater{
		kCtx:        kCtx,
		kCancel:     kCancel,
		storage:     storage,
		outputQueue: queue,
	}
}

func (k *KubernetesRpcUpdater) run() {
	for {
		info := k.outputQueue.Get().(K8SRPCMessage)
		if info.msgType == genesiscommon.TYPE_EXIT {
			break
		}
		log.Debugf("from %s vtap_id %v received cluster_id %s", info.peer, info.vtapID, info.message.GetClusterId())
		// 更新和保存内存数据
		k8sInfo := KubernetesInfo{
			Epoch:     time.Now(),
			ClusterID: info.message.GetClusterId(),
			ErrorMSG:  info.message.GetErrorMsg(),
			VtapID:    info.message.GetVtapId(),
			Version:   info.message.GetVersion(),
			Entries:   info.message.GetEntries(),
		}
		k.storage.Add(k8sInfo)
	}
}

func (k *KubernetesRpcUpdater) Start() {
	go k.run()
}

func (k *KubernetesRpcUpdater) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}
