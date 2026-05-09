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

package updater

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"inet.af/netaddr"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/message/agent"
	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	mmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type bridge struct {
	name string
	uuid string
	vlan int
}

type GenesisSyncRpcUpdater struct {
	orgID           int
	multiNSMode     bool
	singleVPCMode   bool
	nodeIP          string
	defaultVPCName  string
	vmNameField     string
	hostIPsRanges   []netaddr.IPPrefix
	localIPRanges   []netaddr.IPPrefix
	excludeIPRanges []netaddr.IPPrefix
	ignoreNICRegex  *regexp.Regexp
}

func NewGenesisSyncRpcUpdater(orgID int) *GenesisSyncRpcUpdater {
	return &GenesisSyncRpcUpdater{
		orgID:  orgID,
		nodeIP: os.Getenv(ccommon.NODE_IP_KEY),
	}
}

func (v *GenesisSyncRpcUpdater) LoadConfig(config config.GenesisConfig) {
	v.multiNSMode = common.DEFAULT_MULTI_NS_MODE
	v.singleVPCMode = common.DEFAULT_SINGLE_VPC_MODE
	v.defaultVPCName = common.DEFAULT_VPC_NAME
	v.vmNameField = config.VMNameField
	v.localIPRanges = []netaddr.IPPrefix{}
	v.excludeIPRanges = []netaddr.IPPrefix{}
	v.hostIPsRanges = common.IPsToPrefixes(v.orgID, config.HostIPs)
	ignoreNICRegex, err := regexp.Compile(config.IgnoreNICRegex)
	if config.IgnoreNICRegex == "" || err != nil {
		log.Warningf("compile ignore nic regex (%s) failed: %s, use default regex (%s)", config.IgnoreNICRegex, err, common.DEFAULT_IGNORE_NIC_REGEX, logger.NewORGPrefix(v.orgID))
		ignoreNICRegex, _ = regexp.Compile(common.DEFAULT_IGNORE_NIC_REGEX)
	}
	v.ignoreNICRegex = ignoreNICRegex

	db, err := metadb.GetDB(v.orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(v.orgID))
		return
	}

	var azControllerConns []mmodel.AZControllerConnection
	err = db.Find(&azControllerConns).Error
	if err != nil {
		log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
		return
	}
	var currentRegion string
	regionToControllerIPs := map[string][]string{}
	for _, conn := range azControllerConns {
		if v.nodeIP == conn.ControllerIP {
			currentRegion = conn.Region
		}
		regionToControllerIPs[conn.Region] = append(regionToControllerIPs[conn.Region], conn.ControllerIP)
	}
	if currentRegion == "" {
		log.Errorf("current node ip (%s) does not exist in az_controller_connection table", v.nodeIP, logger.NewORGPrefix(v.orgID))
		return
	}

	var domains []mmodel.Domain
	err = db.Where("type = ? AND controller_ip IN ?", ccommon.AGENT_SYNC, regionToControllerIPs[currentRegion]).Find(&domains).Error
	if err != nil {
		log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
		return
	}
	if len(domains) != 1 {
		log.Debugf("current region (%s) agent sync domain is not unique, config from yaml", currentRegion, logger.NewORGPrefix(v.orgID))
		return
	}

	domain := domains[0]
	domainConfigJson, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Errorf("parse domain (%s) config failed: %s", domain.Name, err, logger.NewORGPrefix(v.orgID))
		return
	}

	if value, ok := domainConfigJson.CheckGet("multi_ns_mode"); ok {
		v.multiNSMode = value.MustBool()
	}

	if value, ok := domainConfigJson.CheckGet("single_vpc_mode"); ok {
		v.singleVPCMode = value.MustBool()
	}

	if defaultVPCName := domainConfigJson.Get("default_vpc_name").MustString(); defaultVPCName != "" {
		v.defaultVPCName = defaultVPCName
	}

	if localIPsString := domainConfigJson.Get("local_ip_ranges").MustString(); localIPsString != "" {
		localIPsString = strings.ReplaceAll(localIPsString, "，", ",")
		localIPs := strings.Split(localIPsString, ",")
		v.localIPRanges = common.IPsToPrefixes(v.orgID, localIPs)
	}

	if excludeIPsString := domainConfigJson.Get("exclude_ip_ranges").MustString(); excludeIPsString != "" {
		excludeIPsString = strings.ReplaceAll(excludeIPsString, "，", ",")
		excludeIPs := strings.Split(excludeIPsString, ",")
		v.excludeIPRanges = common.IPsToPrefixes(v.orgID, excludeIPs)
	}

	log.Debugf("update genesis config from domain (%s) config", domain.Name, logger.NewORGPrefix(v.orgID))
}

func (v *GenesisSyncRpcUpdater) ParseVinterfaceInfo(teamID, vtapID uint32, peer, deviceType string, message *agent.GenesisSyncRequest) []model.GenesisVinterface {
	platformData := message.GetPlatformData()
	k8sClusterID := message.GetKubernetesClusterId()
	// 当采集器为容器类型时（cluster id 非空）
	//  - 采集器未注册（vtapID==0），即使没有 Interfaces 也需要处理 vinterface 来让采集器能够注册
	//  - 采集器已经注册（vtapID!=0），采集器重启会出现 Interfaces 为空的情况，为了避免 vinterface 异常增删，不解析当前消息
	if k8sClusterID != "" && len(platformData.Interfaces) == 0 && vtapID != 0 {
		return []model.GenesisVinterface{}
	}

	isContainer := deviceType == common.DEVICE_TYPE_DOCKER_HOST
	epoch := time.Now()
	VIFs := []model.GenesisVinterface{}
	ipAddrs := platformData.GetRawIpAddrs()
	if len(ipAddrs) == 0 {
		log.Errorf("get sync data (raw ip addrs) empty", logger.NewORGPrefix(v.orgID))
		return []model.GenesisVinterface{}
	}
	netNSs := platformData.GetRawIpNetns()
	if len(netNSs) == 0 {
		netNSs = []string{""}
		ipAddrs = ipAddrs[:1]
	}
	if len(ipAddrs) != len(netNSs) {
		log.Error("the quantities of (raw ip addrs) and (raw ip netns) do not match", logger.NewORGPrefix(v.orgID))
		return []model.GenesisVinterface{}
	}
	rootNSMacs := map[string]bool{}
	ifIndexToInterface := map[string]common.Iface{}
	ifNameToInterface := map[string]common.Iface{}
	for i, ipAddr := range ipAddrs {
		nsName := netNSs[i]
		parsedGlobalIPs, err := common.ParseIPOutput(strings.Trim(ipAddr, " "))
		if err != nil {
			log.Errorf("parse ip output error: (%s)", err, logger.NewORGPrefix(v.orgID))
			return []model.GenesisVinterface{}
		}

		for _, item := range parsedGlobalIPs {
			if v.ignoreNICRegex != nil && v.ignoreNICRegex.MatchString(item.Name) {
				continue
			}
			if slices.Contains(common.IGNORE_VINTERFACE_NAME, item.Name) {
				continue
			}
			if item.MAC == "" {
				continue
			}
			// Just take the mac of the root netns
			if i == 0 {
				rootNSMacs[item.MAC] = false
			}
			ifIndexToInterface[fmt.Sprintf("%v%v", nsName, item.Index)] = item
			ifNameToInterface[nsName+item.Name] = item
			vIF := model.GenesisVinterface{
				Name:    item.Name,
				Mac:     item.MAC,
				TapName: item.Name,
				TapMac:  item.MAC,
			}
			ipSlice := []string{}
			for _, ip := range item.IPs {
				if ip.Address == "" || ip.MaskLen == 0 {
					continue
				}
				ipSlice = append(ipSlice, fmt.Sprintf("%s/%v", ip.Address, ip.MaskLen))
			}
			vIF.IPs = strings.Join(ipSlice, ",")
			vIF.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, vIF.Name+vIF.Mac+strconv.Itoa(int(vtapID)))
			vIF.DeviceLcuuid = ccommon.GetUUIDByOrgID(v.orgID, vIF.Name+vIF.Mac+strconv.Itoa(int(vtapID)))
			vIF.DeviceType = deviceType
			vIF.HostIP = peer
			vIF.LastSeen = epoch
			vIF.VtapID = vtapID
			vIF.NodeIP = v.nodeIP
			vIF.KubernetesClusterID = k8sClusterID
			vIF.TeamID = teamID
			VIFs = append(VIFs, vIF)
		}
	}

	deviceIDToMinMAC := map[string]uint64{}
	for _, iface := range platformData.Interfaces {
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
		deviceIDToUUID[key] = ccommon.GetUUIDByOrgID(v.orgID, key+fmt.Sprintf("%d", value))
	}
	for _, iface := range platformData.Interfaces {
		vIF := model.GenesisVinterface{
			Name: iface.GetName(),
			Mac:  common.Uint64ToMac(iface.GetMac()).String(),
		}
		var hasNetMask bool
		var validIPs []string
		for _, addr := range iface.Ip {
			hasNetMask = strings.Contains(addr, `/`)
			var netIP netaddr.IP
			if hasNetMask {
				ipPrefix, err := netaddr.ParseIPPrefix(addr)
				if err != nil {
					log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
					continue
				}
				netIP = ipPrefix.IP()
			} else {
				ipAddr, err := netaddr.ParseIP(addr)
				if err != nil {
					log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
					continue
				}
				netIP = ipAddr
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
			validIPs = append(validIPs, addr)
		}
		vIF.IPs = strings.Join(validIPs, ",")
		vIF.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, vIF.Name+vIF.Mac+vIF.IPs+strconv.Itoa(int(vtapID)))
		ifaceNSName := iface.GetNetns()
		if len(ipAddrs) == 1 {
			ifaceNSName = netNSs[0]
		}
		if gIF, ok := ifIndexToInterface[fmt.Sprintf("%v%v", ifaceNSName, iface.GetTapIndex())]; ok && isContainer {
			vIF.TapName = gIF.Name
			vIF.TapMac = gIF.MAC
		} else if gIF, ok := ifNameToInterface[ifaceNSName+iface.GetName()]; ok && !isContainer {
			vIF.TapName = gIF.Name
			vIF.TapMac = gIF.MAC
		}
		if isContainer {
			if hasNetMask {
				// 拿不到子网的时候不填写该uuid
				vIF.DeviceLcuuid = deviceIDToUUID[iface.GetDeviceId()]
			}
			vIF.DeviceName = fmt.Sprintf("namespace-%s", iface.GetDeviceId())
			vIF.DeviceType = common.DEVICE_TYPE_DOCKER_CONTAINER
			if _, ok := rootNSMacs[vIF.Mac]; ok && v.multiNSMode {
				vIF.DeviceType = common.DEVICE_TYPE_DOCKER_HOST
			}
		} else if deviceType == common.DEVICE_TYPE_KVM_HOST {
			vIF.DeviceLcuuid = iface.GetDeviceId()
			vIF.DeviceName = iface.GetDeviceName()
			vIF.DeviceType = common.DEVICE_TYPE_KVM_VM
		} else {
			// 忽略workload类型
			continue
		}
		vIF.NetnsID = iface.GetNetnsId()
		vIF.IFType = iface.GetIfType()
		vIF.HostIP = peer
		vIF.LastSeen = epoch
		vIF.VtapID = vtapID
		vIF.NodeIP = v.nodeIP
		vIF.KubernetesClusterID = k8sClusterID
		vIF.TeamID = teamID
		VIFs = append(VIFs, vIF)
	}
	return VIFs
}

func (v *GenesisSyncRpcUpdater) ParseVIP(vtapID uint32, message *agent.GenesisSyncRequest) []model.GenesisVIP {
	var vips []model.GenesisVIP

	ipAddrs := message.GetPlatformData().GetRawIpAddrs()
	if len(ipAddrs) == 0 {
		log.Errorf("get sync data (raw ip addrs) empty", logger.NewORGPrefix(v.orgID))
		return []model.GenesisVIP{}
	}
	for _, ipAddr := range ipAddrs {
		parsedGlobalIPs, err := common.ParseIPOutput(strings.Trim(ipAddr, " "))
		if err != nil {
			log.Errorf("parse ip output error: (%s)", err, logger.NewORGPrefix(v.orgID))
			return []model.GenesisVIP{}
		}

		for _, item := range parsedGlobalIPs {
			if item.Name != "lo" {
				continue
			}
			for _, ip := range item.IPs {
				ipObj, err := netaddr.ParseIP(ip.Address)
				if err != nil {
					log.Warningf("parse lo vip (%s) field: (%s)", ip.Address, err, logger.NewORGPrefix(v.orgID))
					continue
				}
				if ipObj.IsLoopback() {
					continue
				}
				vips = append(vips, model.GenesisVIP{
					Lcuuid: ccommon.GetUUIDByOrgID(v.orgID, ip.Address+strconv.Itoa(int(vtapID))),
					IP:     ip.Address,
					VtapID: vtapID,
					NodeIP: v.nodeIP,
				})
			}
		}
	}
	return vips
}

func (v *GenesisSyncRpcUpdater) ParseHostAsVmPlatformInfo(vtapID uint32, peer string, message *agent.GenesisSyncRequest) common.GenesisSyncDataResponse {
	hostName := strings.Trim(message.GetPlatformData().GetRawHostname(), " \n")
	if hostName == "" {
		log.Error("get sync data (raw hostname) empty", logger.NewORGPrefix(v.orgID))
		return common.GenesisSyncDataResponse{}
	}
	ipAddrs := message.GetPlatformData().GetRawIpAddrs()
	if len(ipAddrs) == 0 {
		log.Error("get sync data (raw ip addrs) empty", logger.NewORGPrefix(v.orgID))
		return common.GenesisSyncDataResponse{}
	}
	interfaces, err := common.ParseIPOutput(strings.Trim(ipAddrs[0], " "))
	if err != nil {
		log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
		return common.GenesisSyncDataResponse{}
	}
	vpc := model.GenesisVPC{
		Name:   v.defaultVPCName,
		Lcuuid: ccommon.GetUUIDByOrgID(v.orgID, v.defaultVPCName),
		VtapID: vtapID,
		NodeIP: v.nodeIP,
	}
	// check if vm is behind NAT
	natIP := message.GetNatIp()
	behindNat := peer != natIP
	log.Debugf("host (%s) nat ip is (%s) peer ip is (%s), behind nat: (%t), single vpc mode: (%t)", hostName, natIP, peer, behindNat, v.singleVPCMode, logger.NewORGPrefix(v.orgID))
	if behindNat && !v.singleVPCMode {
		vpc = model.GenesisVPC{
			Name:   "VPC-" + peer,
			Lcuuid: ccommon.GetUUIDByOrgID(v.orgID, "VPC-"+peer),
			VtapID: vtapID,
			NodeIP: v.nodeIP,
		}
	}
	vpcs := []model.GenesisVPC{vpc}

	vm := model.GenesisVM{
		Name:         hostName,
		Label:        hostName,
		Lcuuid:       ccommon.GetUUIDByOrgID(v.orgID, hostName),
		VPCLcuuid:    vpc.Lcuuid,
		LaunchServer: "127.0.0.1",
		State:        ccommon.VM_STATE_RUNNING,
		CreatedAt:    time.Now(),
		VtapID:       vtapID,
		NodeIP:       v.nodeIP,
	}
	vms := []model.GenesisVM{vm}

	nameToNetwork := map[string]model.GenesisNetwork{}
	ports := []model.GenesisPort{}
	ipLastSeens := []model.GenesisIP{}
	for _, iface := range interfaces {
		if iface.MAC == "" || slices.Contains(common.IGNORE_VINTERFACE_NAME, iface.Name) {
			log.Debugf("not found mac or netcard is loopback (%#v)", iface, logger.NewORGPrefix(v.orgID))
			continue
		}
		ips := iface.IPs
		firstIP := common.VifInfo{}
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
		for _, ipItem := range ips {
			// ignore link scope
			if !slices.Contains(common.VALID_SCOPE_NAME, ipItem.Scope) {
				continue
			}
			pIP, err := netaddr.ParseIP(ipItem.Address)
			if err != nil {
				log.Error(err.Error(), logger.NewORGPrefix(v.orgID))
				return common.GenesisSyncDataResponse{}
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
		vType := ccommon.VIF_TYPE_LAN
		netType := ccommon.NETWORK_TYPE_LAN
		if isExternal {
			vType = ccommon.VIF_TYPE_WAN
			netType = ccommon.NETWORK_TYPE_WAN
		}
		if !ok {
			network = model.GenesisNetwork{
				Lcuuid:         ccommon.GetUUIDByOrgID(v.orgID, networkName),
				Name:           networkName,
				SegmentationID: 1,
				VtapID:         vtapID,
				NodeIP:         v.nodeIP,
				VPCLcuuid:      vpc.Lcuuid,
				External:       isExternal,
				NetType:        uint32(netType),
			}
			nameToNetwork[networkName] = network
		}
		port := model.GenesisPort{
			Lcuuid:        ccommon.GetUUIDByOrgID(v.orgID, hostName+iface.MAC),
			Type:          uint32(vType),
			VtapID:        vtapID,
			NodeIP:        v.nodeIP,
			Mac:           iface.MAC,
			DeviceLcuuid:  vm.Lcuuid,
			NetworkLcuuid: network.Lcuuid,
			VPCLcuuid:     vm.VPCLcuuid,
			DeviceType:    ccommon.VIF_DEVICE_TYPE_VM,
		}
		ports = append(ports, port)
		for _, p := range ips {
			// ignore link scope
			if !slices.Contains(common.VALID_SCOPE_NAME, p.Scope) {
				continue
			}
			oIP, err := netaddr.ParseIP(p.Address)
			if err != nil {
				log.Warning(err.Error(), logger.NewORGPrefix(v.orgID))
				continue
			}
			ipLastSeen := model.GenesisIP{
				Lcuuid:           ccommon.GetUUIDByOrgID(v.orgID, hostName+oIP.String()+port.Lcuuid),
				VinterfaceLcuuid: port.Lcuuid,
				IP:               p.Address,
				Masklen:          p.MaskLen,
				VtapID:           vtapID,
				NodeIP:           v.nodeIP,
				LastSeen:         time.Now(),
			}
			ipLastSeens = append(ipLastSeens, ipLastSeen)
		}
	}
	networks := []model.GenesisNetwork{}
	for _, n := range nameToNetwork {
		networks = append(networks, n)
	}

	return common.GenesisSyncDataResponse{
		VMs:         vms,
		VPCs:        vpcs,
		Ports:       ports,
		Networks:    networks,
		IPLastSeens: ipLastSeens,
	}
}

func (v *GenesisSyncRpcUpdater) ParseProcessInfo(vtapID uint32, message *agent.GenesisSyncRequest) []model.GenesisProcess {
	processes := []model.GenesisProcess{}
	if vtapID == 0 {
		return processes
	}

	for _, p := range message.GetProcessData().GetProcessEntries() {
		var osAppTagSlice []string
		for _, tag := range p.GetOsAppTags() {
			osAppTagSlice = append(osAppTagSlice, tag.GetKey()+":"+tag.GetValue())
		}
		osAppTagString := strings.Join(osAppTagSlice, ", ")
		startTime := time.Unix(int64(p.GetStartTime()), 0)
		pID := p.GetPid()
		processes = append(processes, model.GenesisProcess{
			Lcuuid:      ccommon.GetUUIDByOrgID(v.orgID, strconv.Itoa(int(pID))+strconv.Itoa(int(vtapID))+p.GetCmdline()),
			PID:         pID,
			NetnsID:     p.GetNetnsId(),
			Name:        p.GetName(),
			ProcessName: p.GetProcessName(),
			BizType:     int(p.GetBizType()),
			CMDLine:     p.GetCmdline(),
			UserName:    p.GetUser(),
			ContainerID: p.GetContainerId(),
			VtapID:      vtapID,
			NodeIP:      v.nodeIP,
			OSAPPTags:   osAppTagString,
			StartTime:   startTime,
		})
	}
	return processes
}

func (v *GenesisSyncRpcUpdater) ParseKVMPlatformInfo(vtapID uint32, peer string, message *agent.GenesisSyncRequest) common.GenesisSyncDataResponse {
	rawVM := strings.Trim(message.GetPlatformData().GetRawAllVmXml(), " ")
	rawOVSInterface := strings.Trim(message.GetPlatformData().GetRawOvsInterfaces(), " ")
	rawOVSPorts := strings.Trim(message.GetPlatformData().GetRawOvsPorts(), " ")
	ovsMode := false
	if rawOVSPorts != "" {
		ovsMode = true
	}
	rawHostName := strings.Trim(message.GetPlatformData().GetRawHostname(), " \n")
	rawVMStates := strings.Trim(message.GetPlatformData().GetRawVmStates(), " ")
	rawBrctlShow := strings.Trim(message.GetPlatformData().GetRawBrctlShow(), " ")
	rawVlanConfig := strings.Trim(message.GetPlatformData().GetRawVlanConfig(), " ")
	tIPs := message.GetPlatformData().GetIps()
	if ovsMode {
		rawBrctlShow = ""
		rawVlanConfig = ""
	}

	hosts := []model.GenesisHost{
		model.GenesisHost{
			Hostname: rawHostName,
			Lcuuid:   ccommon.GetUUIDByOrgID(v.orgID, rawHostName),
			IP:       peer,
			VtapID:   vtapID,
			NodeIP:   v.nodeIP,
		},
	}

	vpcIDToName := map[string]string{}
	networkIDToNetwork := map[string]model.GenesisNetwork{}
	macToPort := map[string]map[string]string{}
	portToBridge := map[string]bridge{}
	vms := []model.GenesisVM{}
	vpcs := []model.GenesisVPC{}
	ports := []model.GenesisPort{}
	networks := []model.GenesisNetwork{}

	pCSVkeys := []string{"_uuid", "other_config", "tag"}
	nameToOvsPort, err := common.ParseCSVWithKey(rawOVSPorts, "name", pCSVkeys...)
	if err != nil {
		log.Warning("parse csv with key failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
	}
	pCSVs := []string{"name", "external_ids"}
	nameToOvsIfs, err := common.ParseCSV(rawOVSInterface, pCSVs...)
	if err != nil {
		log.Warning("parse csv failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
	}
	for _, nameToOvsIf := range nameToOvsIfs {
		name, ok := nameToOvsIf["name"]
		if !ok {
			continue
		}
		eIDs, err := common.ParseKVString(nameToOvsIf["external_ids"])
		if err != nil {
			log.Warning("parse kvstring failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
		}
		mac, ok := eIDs["attached-mac"]
		if !ok {
			log.Debugf("ovs interface %s does not have external_ids:attached-mac", name, logger.NewORGPrefix(v.orgID))
			continue
		}
		if ovsPort, ok := nameToOvsPort[name]; ok {
			macToPort[mac] = ovsPort
		}
	}
	if !ovsMode {
		bridges, err := common.ParseBrctlShow(rawBrctlShow)
		if err != nil {
			log.Warning("parse brctl show failed: " + err.Error())
		}
		vlanConfig, err := common.ParseVLANConfig(rawVlanConfig)
		if err != nil {
			log.Warning("parse vlan config failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
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
				uuid: ccommon.GetUUIDByOrgID(v.orgID, fmt.Sprintf("%d,%s", vlan, br)),
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
		ipObj := net.IP(tIP.GetIp())
		nIPObj, ok := netaddr.FromStdIP(ipObj)
		if !ok {
			log.Warningf("ip (%s) invalid", ipObj.String(), logger.NewORGPrefix(v.orgID))
			continue
		}
		ip.IP = ipObj.String()
		tIPLastSeen := tIP.GetLastSeen()
		ip.LastSeen = time.Unix(int64(tIPLastSeen), 0).Local()
		ip.VtapID = vtapID
		ip.NodeIP = v.nodeIP
		macStr := common.Uint64ToMac(tIP.GetMac()).String()
		macToIPs[macStr] = append(macToIPs[macStr], ip)
		cFlag := true
		for _, l := range v.localIPRanges {
			if l.Contains(nIPObj) {
				cFlag = false
				break
			}
		}
		macToIsExternalIP[macStr] = cFlag
	}

	ips := []model.GenesisIP{}
	vmStates, err := common.ParseVMStates(rawVMStates)
	if err != nil {
		log.Warning("parse vm states failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
	}
	xmlVMs, err := common.ParseVMXml(rawVM, v.vmNameField)
	if err != nil {
		log.Warning("parse vm xml failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
	}
	for _, xmlVM := range xmlVMs {
		vm := model.GenesisVM{}
		vm.VtapID = vtapID
		vm.NodeIP = v.nodeIP
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
			vm.State = uint32(ccommon.VM_STATE_EXCEPTION)
		}
		vms = append(vms, vm)

		if vm.State != uint32(ccommon.VM_STATE_RUNNING) {
			// 不处理非运行状态虚拟机的接口
			continue
		}

		for _, xmlIf := range xmlVM.Interfaces {
			port := model.GenesisPort{}
			network := model.GenesisNetwork{}
			mac := strings.ToLower(xmlIf.Mac)
			ifName := xmlIf.Target
			if ovsMode {
				portMap := map[string]string{}
				if mP, ok := macToPort[mac]; ok {
					portMap = mP
				} else if oP, ok := nameToOvsPort[ifName]; ok {
					portMap = oP
				} else {
					log.Debugf("vm %s interface %s mac %s not found in ovs ports", vm.Label, ifName, mac, logger.NewORGPrefix(v.orgID))
					continue
				}
				port.Lcuuid = portMap["_uuid"]
				options, err := common.ParseKVString(portMap["other_config"])
				if err != nil {
					log.Warning("parse kv string failed: "+err.Error(), logger.NewORGPrefix(v.orgID))
				}
				if nLcuuid, ok := options["net_uuid"]; ok {
					network.Lcuuid = nLcuuid
				} else {
					// tag不为数字时均默认为1
					tagInt, err := strconv.Atoi(portMap["tag"])
					if err != nil {
						tagInt = 1
					}
					network.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, strconv.Itoa(tagInt))
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
						uuid: ccommon.GetUUIDByOrgID(v.orgID, "yunshan-temp"),
						vlan: 1,
					}
				}
				port.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, mac)
				network.Lcuuid = br.uuid
				network.SegmentationID = uint32(br.vlan)
			}

			isExternal := false
			if isE, ok := macToIsExternalIP[mac]; ok {
				isExternal = isE
			}
			network.NetType = uint32(ccommon.NETWORK_TYPE_LAN)
			port.Type = uint32(ccommon.VIF_TYPE_LAN)
			if isExternal {
				network.NetType = uint32(ccommon.NETWORK_TYPE_WAN)
				port.Type = uint32(ccommon.VIF_TYPE_WAN)
			}
			network.External = isExternal
			network.VPCLcuuid = vm.VPCLcuuid
			network.VtapID = vtapID
			network.NodeIP = v.nodeIP
			network.Name = "subnet_vni_" + strconv.Itoa(int(network.SegmentationID))
			networkIDToNetwork[network.Lcuuid] = network
			port.Mac = mac
			port.DeviceLcuuid = vm.Lcuuid
			port.NetworkLcuuid = network.Lcuuid
			port.VPCLcuuid = vm.VPCLcuuid
			port.VtapID = vtapID
			port.NodeIP = v.nodeIP
			port.DeviceType = ccommon.VIF_DEVICE_TYPE_VM
			ports = append(ports, port)
			for _, ip := range macToIPs[mac] {
				ip.VinterfaceLcuuid = port.Lcuuid
				ip.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, ip.IP+ip.VinterfaceLcuuid)
				ips = append(ips, ip)
			}
		}
	}

	for _, n := range networkIDToNetwork {
		networks = append(networks, n)
	}
	for id, name := range vpcIDToName {
		vpc := model.GenesisVPC{}
		vpc.VtapID = vtapID
		vpc.NodeIP = v.nodeIP
		vpc.Lcuuid = id
		vpc.Name = name
		vpcs = append(vpcs, vpc)
	}

	lldps := []model.GenesisLldp{}
	for _, l := range message.GetPlatformData().GetLldpInfo() {
		lldp := model.GenesisLldp{}
		lldp.Lcuuid = ccommon.GetUUIDByOrgID(v.orgID, peer+l.GetManagementAddress()+l.GetPortId())
		lldp.HostIP = peer
		lldp.VtapID = vtapID
		lldp.NodeIP = v.nodeIP
		lldp.HostInterface = l.GetInterface()
		lldp.SystemName = l.GetSystemName()
		lldp.ManagementAddress = l.GetManagementAddress()
		lldp.VinterfaceLcuuid = l.GetPortId()
		lldp.VinterfaceDescription = l.GetPortDescription()
		lldp.LastSeen = time.Now()
		lldps = append(lldps, lldp)
	}

	return common.GenesisSyncDataResponse{
		Hosts:       hosts,
		VMs:         vms,
		VPCs:        vpcs,
		Networks:    networks,
		Ports:       ports,
		IPLastSeens: ips,
		Lldps:       lldps,
	}
}

func (v *GenesisSyncRpcUpdater) UnmarshalProtobuf(teamID, vtapID uint32, peer string, message *agent.GenesisSyncRequest) common.GenesisSyncDataResponse {
	genesisSyncData := common.GenesisSyncDataResponse{}
	if common.IPInRanges(peer, v.hostIPsRanges...) && message.GetPlatformData().GetPlatformEnabled() {
		genesisSyncData = v.ParseKVMPlatformInfo(vtapID, peer, message)
	}

	genesisSyncData.Processes = v.ParseProcessInfo(vtapID, message)
	genesisSyncData.Vinterfaces = v.ParseVinterfaceInfo(teamID, vtapID, peer, common.DEVICE_TYPE_KVM_HOST, message)

	return genesisSyncData
}

func (v *GenesisSyncRpcUpdater) UnmarshalKubernetesProtobuf(teamID, vtapID uint32, peer string, enabled bool, message *agent.GenesisSyncRequest) common.GenesisSyncDataResponse {
	genesisSyncData := common.GenesisSyncDataResponse{}
	if enabled {
		genesisSyncData = v.ParseHostAsVmPlatformInfo(vtapID, peer, message)
	}

	genesisSyncData.Processes = v.ParseProcessInfo(vtapID, message)
	genesisSyncData.Vinterfaces = v.ParseVinterfaceInfo(teamID, vtapID, peer, common.DEVICE_TYPE_DOCKER_HOST, message)

	return genesisSyncData
}

func (v *GenesisSyncRpcUpdater) UnmarshalWorkloadProtobuf(teamID, vtapID uint32, peer, deviceType string, enabled bool, message *agent.GenesisSyncRequest) common.GenesisSyncDataResponse {
	genesisSyncData := common.GenesisSyncDataResponse{}
	if enabled {
		genesisSyncData = v.ParseHostAsVmPlatformInfo(vtapID, peer, message)
	}

	genesisSyncData.VIPs = v.ParseVIP(vtapID, message)
	genesisSyncData.Processes = v.ParseProcessInfo(vtapID, message)
	genesisSyncData.Vinterfaces = v.ParseVinterfaceInfo(teamID, vtapID, peer, deviceType, message)

	return genesisSyncData
}
