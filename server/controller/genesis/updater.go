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

	tridentcommon "github.com/deepflowys/deepflow/message/common"
	"github.com/deepflowys/deepflow/message/trident"
	"github.com/deepflowys/deepflow/server/controller/common"
	genesiscommon "github.com/deepflowys/deepflow/server/controller/genesis/common"
	"github.com/deepflowys/deepflow/server/controller/genesis/config"
	"github.com/deepflowys/deepflow/server/controller/model"
	"github.com/deepflowys/deepflow/server/libs/queue"
	uuid "github.com/satori/go.uuid"
)

type bridge struct {
	name string
	uuid string
	vlan int
}

type GenesisSyncRpcUpdater struct {
	vCtx                  context.Context
	vCancel               context.CancelFunc
	storage               *SyncStorage
	outputQueue           queue.QueueReader
	hostIPsMap            map[string]int
	localIPRanges         []netaddr.IPPrefix
	excludeIPRanges       []netaddr.IPPrefix
	genesisSyncDataByPeer map[uint32]GenesisSyncDataOperation
}

func NewGenesisSyncRpcUpdater(storage *SyncStorage, queue queue.QueueReader, cfg config.GenesisConfig, ctx context.Context) *GenesisSyncRpcUpdater {
	hostIPsMap := map[string]int{}
	for _, h := range cfg.HostIPs {
		_, err := netaddr.ParseIP(h)
		if err != nil {
			log.Error("parse host ips error: " + err.Error())
			continue
		}
		hostIPsMap[h] = 0
	}

	localIPRanges := []netaddr.IPPrefix{}
	if len(cfg.LocalIPRanges) > 0 {
		for _, l := range cfg.LocalIPRanges {
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
	if len(cfg.ExcludeIPRanges) > 0 {
		for _, e := range cfg.ExcludeIPRanges {
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
		hostIPsMap:            hostIPsMap,
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
	ipAddrs := info.GetRawIpAddrs()
	if len(ipAddrs) == 0 {
		log.Errorf("get sync data (raw ip addrs) empty")
		return VIFs
	}
	parsedGlobalIPs, err := genesiscommon.ParseIPOutput(ipAddrs[0])
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
	ipAddrs := info.GetRawIpAddrs()
	if len(ipAddrs) == 0 {
		log.Errorf("get sync data (raw ip addrs) empty")
		return GenesisSyncDataOperation{}
	}
	interfaces, err := genesiscommon.ParseIPOutput(strings.Trim(ipAddrs[0], " "))
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

func (v *GenesisSyncRpcUpdater) ParseKVMPlatformInfo(info *trident.GenesisPlatformData, peer string, vtapID uint32) GenesisSyncDataOperation {
	rawVM := strings.Trim(info.GetRawAllVmXml(), " ")
	rawOVSInterface := strings.Trim(info.GetRawOvsInterfaces(), " ")
	rawOVSPorts := strings.Trim(info.GetRawOvsPorts(), " ")
	ovsMode := false
	if rawOVSPorts != "" {
		ovsMode = true
	}
	rawHostName := strings.Trim(info.GetRawHostname(), " \n")
	rawVMStates := strings.Trim(info.GetRawVmStates(), " ")
	rawBrctlShow := strings.Trim(info.GetRawBrctlShow(), " ")
	rawVlanConfig := strings.Trim(info.GetRawVlanConfig(), " ")
	tIPs := info.GetIps()
	if ovsMode {
		rawBrctlShow = ""
		rawVlanConfig = ""
	}

	hosts := []model.GenesisHost{
		model.GenesisHost{
			Hostname: rawHostName,
			Lcuuid:   common.GetUUID(rawHostName, uuid.Nil),
			IP:       peer,
			VtapID:   vtapID,
		},
	}

	vpcIDToName := map[string]string{}
	networkIDToNetwork := map[string]model.GenesisNetwork{}
	macToPort := map[string]map[string]string{}
	portToBridge := map[string]bridge{}
	vms := []model.GenesisVM{}
	vpcs := []model.GenesisVpc{}
	ports := []model.GenesisPort{}
	networks := []model.GenesisNetwork{}

	pCSVkeys := []string{"_uuid", "other_config", "tag"}
	nameToOvsPort, err := genesiscommon.ParseCSVWithKey(rawOVSPorts, "name", pCSVkeys...)
	if err != nil {
		log.Warning("parse csv with key failed: " + err.Error())
	}
	pCSVs := []string{"name", "external_ids"}
	nameToOvsIfs, err := genesiscommon.ParseCSV(rawOVSInterface, pCSVs...)
	if err != nil {
		log.Warning("parse csv failed: " + err.Error())
	}
	for _, nameToOvsIf := range nameToOvsIfs {
		name, ok := nameToOvsIf["name"]
		if !ok {
			continue
		}
		eIDs, err := genesiscommon.ParseKVString(nameToOvsIf["external_ids"])
		if err != nil {
			log.Warning("parse kvstring failed: " + err.Error())
		}
		mac, ok := eIDs["attached-mac"]
		if !ok {
			log.Debugf("ovs interface %s does not have external_ids:attached-mac", name)
			continue
		}
		if ovsPort, ok := nameToOvsPort[name]; ok {
			macToPort[mac] = ovsPort
		}
	}
	if !ovsMode {
		bridges, err := genesiscommon.ParseBrctlShow(rawBrctlShow)
		if err != nil {
			log.Warning("parse brctl show failed: " + err.Error())
		}
		vlanConfig, err := genesiscommon.ParseVLANConfig(rawVlanConfig)
		if err != nil {
			log.Warning("parse vlan config failed: " + err.Error())
		}
		for br, ifaces := range bridges {
			vlan := 1
			for _, iface := range ifaces {
				if v, ok := vlanConfig[iface]; ok {
					vlan = v
					break
				}
			}
			bge := bridge{
				name: br,
				uuid: common.GetUUID(fmt.Sprintf("%d,%s", vlan, br), uuid.Nil),
				vlan: vlan,
			}
			for _, iface := range ifaces {
				portToBridge[iface] = bge
			}
		}
	}

	macToIPs := map[string][]model.GenesisIP{}
	macToIsExternalIP := map[string]bool{}
	for _, tIP := range tIPs {
		ip := model.GenesisIP{}
		tIPStr := string(tIP.GetIp())
		ipObj, err := netaddr.ParseIP(tIPStr)
		if err != nil {
			log.Warning("invalid ip address found: " + tIPStr)
			continue
		}
		ip.IP = ipObj.String()
		tIPLastSeen := tIP.GetLastSeen()
		ip.LastSeen = time.Unix(int64(tIPLastSeen), 0).Local()
		ip.VtapID = vtapID
		macStr := genesiscommon.Uint64ToMac(tIP.GetMac()).String()
		if _, ok := macToIPs[macStr]; ok {
			macToIPs[macStr] = append(macToIPs[macStr], ip)
		} else {
			macToIPs[macStr] = []model.GenesisIP{ip}
		}
		cFlag := false
		for _, l := range v.localIPRanges {
			if !l.Contains(ipObj) {
				cFlag = true
			}
		}
		macToIsExternalIP[macStr] = cFlag
	}

	ips := []model.GenesisIP{}
	vmStates, err := genesiscommon.ParseVMStates(rawVMStates)
	if err != nil {
		log.Warning("parse vm states failed: " + err.Error())
	}
	xmlVMs, err := genesiscommon.ParseVMXml(rawVM)
	if err != nil {
		log.Warning("parse vm xml failed: " + err.Error())
	}
	for _, xmlVM := range xmlVMs {
		vm := model.GenesisVM{}
		vm.VtapID = vtapID
		vm.Lcuuid = xmlVM.UUID
		vm.Name = xmlVM.Name
		vm.Label = xmlVM.Label
		vm.CreatedAt = time.Now()
		if xmlVM.VPC.Name != "" && xmlVM.VPC.UUID != "" {
			vm.VPCLcuuid = xmlVM.VPC.UUID
			vpcIDToName[xmlVM.VPC.UUID] = xmlVM.VPC.Name
		}
		vm.LaunchServer = peer
		state, ok := vmStates[xmlVM.Label]
		if ok {
			vm.State = uint32(state)
		} else {
			vm.State = uint32(common.VM_STATE_EXCEPTION)
		}
		vms = append(vms, vm)

		if vm.State != uint32(common.VM_STATE_RUNNING) {
			// 不处理非运行状态虚拟机的接口
			continue
		}

		for _, xmlIf := range xmlVM.Interfaces {
			port := model.GenesisPort{}
			network := model.GenesisNetwork{}
			mac := xmlIf.Mac
			ifName := xmlIf.Target
			if ovsMode {
				portMap := map[string]string{}
				if mP, ok := macToPort[mac]; ok {
					portMap = mP
				} else if oP, ok := nameToOvsPort[ifName]; ok {
					portMap = oP
				} else {
					log.Debugf("vm %s interface %s mac %s not found in ovs ports", vm.Label, ifName, mac)
					continue
				}
				port.Lcuuid = portMap["_uuid"]
				options, err := genesiscommon.ParseKVString(portMap["other_config"])
				if err != nil {
					log.Warning("parse kv string failed: " + err.Error())
				}
				if nLcuuid, ok := options["net_uuid"]; ok {
					network.Lcuuid = nLcuuid
				} else {
					// tag不为数字时均默认为1
					tagInt, err := strconv.Atoi(portMap["tag"])
					if err != nil {
						tagInt = 1
					}
					network.Lcuuid = common.GetUUID(strconv.Itoa(tagInt), uuid.Nil)
				}
				if sID, ok := options["segmentation_id"]; ok {
					sIDInt, err := strconv.Atoi(sID)
					if err != nil {
						sIDInt = 1
					}
					network.SegmentationID = uint32(sIDInt)
				} else {
					tagInt, err := strconv.Atoi(portMap["tag"])
					if err != nil {
						tagInt = 1
					}
					network.SegmentationID = uint32(tagInt)
				}
			} else {
				br, ok := portToBridge[ifName]
				if !ok {
					br = bridge{
						uuid: common.GetUUID("yunshan-temp", uuid.Nil),
						vlan: 1,
					}
				}
				port.Lcuuid = common.GetUUID(mac, uuid.Nil)
				network.Lcuuid = br.uuid
				network.SegmentationID = uint32(br.vlan)
			}

			isExternal := false
			if isE, ok := macToIsExternalIP[mac]; ok {
				isExternal = isE
			}
			network.NetType = uint32(common.NETWORK_TYPE_LAN)
			port.Type = uint32(common.VIF_TYPE_LAN)
			if isExternal {
				network.NetType = uint32(common.NETWORK_TYPE_WAN)
				port.Type = uint32(common.VIF_TYPE_WAN)
			}
			network.External = isExternal
			network.VPCLcuuid = vm.VPCLcuuid
			network.VtapID = vtapID
			network.Name = "subnet_vni_" + strconv.Itoa(int(network.SegmentationID))
			networkIDToNetwork[network.Lcuuid] = network
			port.Mac = mac
			port.DeviceLcuuid = vm.Lcuuid
			port.NetworkLcuuid = network.Lcuuid
			port.VPCLcuuid = vm.VPCLcuuid
			port.VtapID = vtapID
			port.DeviceType = common.VIF_DEVICE_TYPE_VM
			ports = append(ports, port)
			for _, ip := range macToIPs[mac] {
				ip.VinterfaceLcuuid = port.Lcuuid
				ip.Lcuuid = common.GetUUID(ip.IP+ip.VinterfaceLcuuid, uuid.Nil)
				ips = append(ips, ip)
			}
		}
	}

	for _, n := range networkIDToNetwork {
		networks = append(networks, n)
	}
	for id, name := range vpcIDToName {
		vpc := model.GenesisVpc{}
		vpc.VtapID = vtapID
		vpc.Lcuuid = id
		vpc.Name = name
		vpcs = append(vpcs, vpc)
	}

	lldps := []model.GenesisLldp{}
	for _, l := range info.GetLldpInfo() {
		lldp := model.GenesisLldp{}
		lldp.Lcuuid = common.GetUUID(peer+l.GetManagementAddress()+l.GetPortId(), uuid.Nil)
		lldp.HostIP = peer
		lldp.VtapID = vtapID
		lldp.HostInterface = l.GetInterface()
		lldp.SystemName = l.GetSystemName()
		lldp.ManagementAddress = l.GetManagementAddress()
		lldp.VinterfaceLcuuid = l.GetPortId()
		lldp.VinterfaceDescription = l.GetPortDescription()
		lldp.LastSeen = time.Now()
		lldps = append(lldps, lldp)
	}

	return GenesisSyncDataOperation{
		Hosts:       NewHostPlatformDataOperation(hosts),
		VMs:         NewVMPlatformDataOperation(vms),
		VPCs:        NewVpcPlatformDataOperation(vpcs),
		Networks:    NewNetworkPlatformDataOperation(networks),
		Ports:       NewPortPlatformDataOperation(ports),
		IPlastseens: NewIPLastSeenPlatformDataOperation(ips),
		Lldps:       NewLldpInfoPlatformDataOperation(lldps),
	}
}

func (v *GenesisSyncRpcUpdater) UnmarshalProtobuf(info *trident.GenesisPlatformData, peer string, vtapID uint32, k8sClusterID string) GenesisSyncDataOperation {
	vifs := v.ParseVinterfaceInfo(info, peer, vtapID, k8sClusterID, genesiscommon.DEVICE_TYPE_KVM_HOST)
	genesisSyncDataOper := GenesisSyncDataOperation{}
	vinterfaces := NewVinterfacePlatformDataOperation(vifs)
	if _, ok := v.hostIPsMap[peer]; ok && info.GetPlatformEnabled() {
		genesisSyncDataOper = v.ParseKVMPlatformInfo(info, peer, vtapID)
	}
	genesisSyncDataOper.Vinterfaces = vinterfaces

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
			log.Warningf("from (%s) vtap_id (%v) type (%v)", info.peer, info.vtapID, info.msgType)
			continue
		}

		log.Debugf("received (%s) vtap_id (%v) type (%v) received (%s)", info.peer, info.vtapID, info.msgType, info.message)

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
