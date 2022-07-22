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
	"fmt"
	"strconv"
	"strings"
	"time"

	"inet.af/netaddr"

	uuid "github.com/satori/go.uuid"

	tridentcommon "github.com/deepflowys/deepflow/message/common"
	"github.com/deepflowys/deepflow/message/trident"
	"github.com/deepflowys/deepflow/server/controller/common"
	genesiscommon "github.com/deepflowys/deepflow/server/controller/genesis/common"
	"github.com/deepflowys/deepflow/server/controller/model"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type GenesisSyncRpcUpdater struct {
	vCtx                  context.Context
	vCancel               context.CancelFunc
	storage               *SyncStorage
	outputQueue           queue.QueueReader
	localIPRanges         []netaddr.IPPrefix
	excludeIPRanges       []netaddr.IPPrefix
	genesisSyncDataByPeer map[uint32]GenesisSyncDataOperation
}

func NewGenesisSyncRpcUpdater(storage *SyncStorage, queue queue.QueueReader, localIPString, excludeIPString []string, ctx context.Context) *GenesisSyncRpcUpdater {
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
	return &GenesisSyncRpcUpdater{
		vCtx:                  vCtx,
		vCancel:               vCancel,
		storage:               storage,
		outputQueue:           queue,
		localIPRanges:         localIPRanges,
		excludeIPRanges:       excludeIPRanges,
		genesisSyncDataByPeer: map[uint32]GenesisSyncDataOperation{},
	}
}

func (v *GenesisSyncRpcUpdater) ParseVinterfaceInfo(info *trident.GenesisPlatformData, peer string, vtapID uint32, k8sClusterID, deviceType string) []model.GenesisVinterface {
	var isContainer bool
	if deviceType == genesiscommon.DEVICE_TYPE_DOCKER_HOST {
		isContainer = true
	}
	epoch := time.Now()
	VIFs := []model.GenesisVinterface{}
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
		vIF := model.GenesisVinterface{
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
		vIF.Lcuuid = common.GetUUID(vIF.Name+vIF.Mac+strconv.Itoa(int(vtapID)), uuid.Nil)
		vIF.DeviceLcuuid = common.GetUUID(vIF.Name+vIF.Mac+strconv.Itoa(int(vtapID)), uuid.Nil)
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
		vIF := model.GenesisVinterface{
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
		vIF.Lcuuid = common.GetUUID(vIF.Name+vIF.Mac+vIF.IPs+strconv.Itoa(int(vtapID)), uuid.Nil)
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

func (v *GenesisSyncRpcUpdater) ParseHostAsVmPlatformInfo(info *trident.GenesisPlatformData, peer, natIP string, vtapID uint32) GenesisSyncDataOperation {
	hostName := strings.Trim(info.GetRawHostname(), " \n")
	interfaces, err := genesiscommon.ParseIPOutput(strings.Trim(info.GetRawIpAddrs()[0], " "))
	if err != nil {
		log.Error(err.Error())
		return GenesisSyncDataOperation{}
	}
	// check if vm is behind NAT
	behindNat := peer != natIP
	vpc := model.GenesisVpc{
		Name:   "default-public-cloud-vpc",
		Lcuuid: common.GetUUID("default-public-cloud-vpc", uuid.Nil),
		VtapID: vtapID,
	}
	if behindNat {
		vpc = model.GenesisVpc{
			Name:   "VPC-" + peer,
			Lcuuid: common.GetUUID("VPC-"+peer, uuid.Nil),
			VtapID: vtapID,
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
		VtapID:       vtapID,
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
				return GenesisSyncDataOperation{}
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
				VtapID:         vtapID,
				VPCLcuuid:      vpc.Lcuuid,
				External:       isExternal,
				NetType:        uint32(netType),
			}
			nameToNetwork[networkName] = network
		}
		port := model.GenesisPort{
			Lcuuid:        common.GetUUID(hostName+iface.MAC, uuid.Nil),
			Type:          uint32(vType),
			VtapID:        vtapID,
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
				VtapID:           vtapID,
				LastSeen:         time.Now(),
			}
			ipLastSeens = append(ipLastSeens, ipLastSeen)
		}
	}
	networks := []model.GenesisNetwork{}
	for _, n := range nameToNetwork {
		networks = append(networks, n)
	}
	return GenesisSyncDataOperation{
		VMs:         NewVMPlatformDataOperation(vms),
		VPCs:        NewVpcPlatformDataOperation(vpcs),
		Ports:       NewPortPlatformDataOperation(ports),
		Networks:    NewNetworkPlatformDataOperation(networks),
		IPlastseens: NewIPLastSeenPlatformDataOperation(ipLastSeens),
	}
}

func (v *GenesisSyncRpcUpdater) UnmarshalProtobuf(info *trident.GenesisPlatformData, peer string, vtapID uint32, k8sClusterID string) GenesisSyncDataOperation {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_KVM_HOST)
	genesisSyncDataOper := GenesisSyncDataOperation{}
	genesisSyncDataOper.Vinterfaces = NewVinterfacePlatformDataOperation(vifs)

	return genesisSyncDataOper
}

func (v *GenesisSyncRpcUpdater) UnmarshalKubernetesProtobuf(info *trident.GenesisPlatformData, peer, natIP string, vtapID uint32, k8sClusterID string) GenesisSyncDataOperation {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_DOCKER_HOST)
	genesisSyncDataOper := GenesisSyncDataOperation{}
	vinterfaces := NewVinterfacePlatformDataOperation(vifs)
	if info.GetPlatformEnabled() {
		genesisSyncDataOper = v.ParseHostAsVmPlatformInfo(info, peer, natIP, vtapID)
	}
	genesisSyncDataOper.Vinterfaces = vinterfaces

	return genesisSyncDataOper
}

func (v *GenesisSyncRpcUpdater) UnmarshalWorkloadProtobuf(info *trident.GenesisPlatformData, peer, natIP string, vtapID uint32, k8sClusterID, tridentType string) GenesisSyncDataOperation {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, tridentType)
	genesisSyncDataOper := GenesisSyncDataOperation{}
	vinterfaces := NewVinterfacePlatformDataOperation(vifs)
	if info.GetPlatformEnabled() {
		genesisSyncDataOper = v.ParseHostAsVmPlatformInfo(info, peer, natIP, vtapID)
	}
	genesisSyncDataOper.Vinterfaces = vinterfaces

	return genesisSyncDataOper
}

func (v *GenesisSyncRpcUpdater) run() {
	for {
		genesisSyncDataOper := GenesisSyncDataOperation{}
		info := v.outputQueue.Get().(VIFRPCMessage)
		if info.msgType == genesiscommon.TYPE_EXIT {
			continue
			log.Warningf("from (%s) vtap_id (%v) type (%v)", info.peer, info.vtapID, info.msgType)
		}
		log.Debugf("from (%s) vtap_id (%v) type (%v) received (%s)", info.peer, info.vtapID, info.msgType, info.message)
		if info.msgType == genesiscommon.TYPE_RENEW {
			if info.vtapID != 0 {
				peerInfo, ok := v.genesisSyncDataByPeer[info.vtapID]
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
				genesisSyncDataOper = v.UnmarshalWorkloadProtobuf(infoData, info.peer, natIP, info.vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_PHYSICAL_MACHINE)
			} else if tridentType == tridentcommon.TridentType_TT_PUBLIC_CLOUD {
				genesisSyncDataOper = v.UnmarshalWorkloadProtobuf(infoData, info.peer, natIP, info.vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_PUBLIC_CLOUD)
			} else if tridentType == tridentcommon.TridentType_TT_HOST_POD || tridentType == tridentcommon.TridentType_TT_VM_POD {
				genesisSyncDataOper = v.UnmarshalKubernetesProtobuf(infoData, info.peer, natIP, info.vtapID, k8sClusterID)
			} else {
				genesisSyncDataOper = v.UnmarshalProtobuf(infoData, info.peer, info.vtapID, k8sClusterID)
			}
			if info.vtapID != 0 {
				v.genesisSyncDataByPeer[info.vtapID] = genesisSyncDataOper
			}
			v.storage.Update(genesisSyncDataOper, info.vtapID)
		}
	}
}

func (v *GenesisSyncRpcUpdater) Start() {
	go v.run()
}

func (v *GenesisSyncRpcUpdater) Stop() {
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
