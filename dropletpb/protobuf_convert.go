package dropletpb

import (
	"net"
	"strings"

	"gitlab.x.lan/yunshan/message/trident"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

func newPlatformData(vifData *trident.Interface) *datatype.PlatformData {
	macInt := vifData.GetMac()
	hostIp := uint32(0)
	ip := ParserStringIpV4(vifData.GetLaunchServer())
	if ip != nil {
		hostIp = IpToUint32(ip)
	}

	ips := make([]*datatype.IpNet, 0, 1024)
	for _, ipResource := range vifData.IpResources {
		fixIp := ParserStringIp(ipResource.GetIp())
		if fixIp == nil {
			continue
		}

		netmask := ipResource.GetMasklen()
		max := uint32(datatype.MAX_MASK_LEN)
		min := uint32(datatype.MIN_MASK_LEN)
		if len(fixIp) != 4 {
			max = uint32(datatype.MAX_MASK6_LEN)
		}
		if netmask > max {
			netmask = max
		} else if netmask < min {
			netmask = min
		}

		ipinfo := &datatype.IpNet{
			RawIp:    fixIp,
			Netmask:  netmask,
			SubnetId: ipResource.GetSubnetId(),
		}
		ips = append(ips, ipinfo)
	}

	epcId := int32(vifData.GetEpcId())
	if epcId > 0 {
		epcId &= 0xffff
	} else if epcId == 0 {
		epcId = datatype.EPC_FROM_DEEPFLOW
	}

	return &datatype.PlatformData{
		Mac:        macInt,
		TapMac:     vifData.GetTapMac(),
		Ips:        ips,
		EpcId:      epcId,
		DeviceType: vifData.GetDeviceType(),
		DeviceId:   vifData.GetDeviceId() & 0xffff,
		IfType:     vifData.GetIfType(),
		HostIp:     hostIp,
	}
}

// response.GetPlatformData().GetInterfaces()
func Convert2PlatformData(interfaces []*trident.Interface) []*datatype.PlatformData {
	platformDatas := make([]*datatype.PlatformData, 0, len(interfaces))
	for _, data := range interfaces {
		if newData := newPlatformData(data); newData != nil {
			platformDatas = append(platformDatas, newData)
		}
	}
	return platformDatas
}

func newIpGroupData(ipGroup *trident.Group) *policy.IpGroupData {
	if ipGroup == nil || (ipGroup.GetIps() == nil && ipGroup.GetIpRanges() == nil) {
		return nil
	}

	ips := make([]string, 0, len(ipGroup.GetIps()))
	if ipGroup.GetIps() != nil {
		ips = ipGroup.GetIps()
	}
	if ipGroup.GetIpRanges() != nil {
		for _, ipRange := range ipGroup.GetIpRanges() {
			ipPeers := strings.Split(ipRange, "-")
			if ipPeers == nil || len(ipPeers) != 2 {
				continue
			}
			startIp := ParserStringIp(ipPeers[0])
			endIp := ParserStringIp(ipPeers[1])
			if startIp == nil || endIp == nil {
				continue
			}
			for _, ip := range datatype.IpRangeConvert2CIDR(startIp, endIp) {
				ips = append(ips, ip.String())
			}
		}
	}
	vmIds := make([]uint32, 0, len(ipGroup.GetVmIds()))
	for _, id := range ipGroup.GetVmIds() {
		vmIds = append(vmIds, id&0xffff)
	}

	return &policy.IpGroupData{
		Id:    ipGroup.GetId() & 0xffff,
		EpcId: int32(ipGroup.GetEpcId() & 0xffff),
		Type:  uint8(ipGroup.GetType()),
		Ips:   ips,
		VmIds: vmIds,
	}
}

// response.GetPlatformData().GetIpGroups()
func Convert2IpGroupData(ipGroups []*trident.Group) []*policy.IpGroupData {
	ipGroupDatas := make([]*policy.IpGroupData, 0, len(ipGroups))
	for _, group := range ipGroups {
		if newData := newIpGroupData(group); newData != nil {
			ipGroupDatas = append(ipGroupDatas, newData)
		}
	}

	return ipGroupDatas
}

func updateTunnelIpMap(flowAcls []*trident.FlowAcl) {
	tunnelIps := make(map[uint16]net.IP, 8)

	for _, acl := range flowAcls {
		for _, npb := range acl.GetNpbActions() {
			tunnelType := uint8(npb.GetTunnelType())
			ip := net.ParseIP(npb.GetTunnelIp())
			if ip == nil || tunnelType == datatype.NPB_TUNNEL_TYPE_PCAP {
				continue
			}
			ipId := uint16(npb.GetTunnelIpId() & 0xffff)

			if ip.To4() != nil {
				ip = ip.To4()
			}
			tunnelIps[ipId] = ip
		}
	}
	datatype.UpdateTunnelIps(tunnelIps)
}

func newAclAction(actions []*trident.FlowAction) []datatype.AclAction {
	actionSet := make(map[datatype.AclAction]datatype.AclAction)
	for _, action := range actions {
		actionFlags := datatype.ActionFlag(1 << uint32(action.GetAction()-1)) // protobuf中的定义从1开始
		tagTemplates := datatype.TagTemplate(action.GetTagTemplate())
		key := datatype.AclAction(0).SetACLGID(0).AddActionFlags(actionFlags)
		if aclAction, find := actionSet[key]; find {
			actionSet[key] = aclAction.AddTagTemplates(tagTemplates)
		} else {
			actionSet[key] = datatype.AclAction(0).SetACLGID(0).AddActionFlags(actionFlags).AddTagTemplates(tagTemplates)
		}
		for _, aclGID := range action.GetPolicyAclGroupId() {
			key = datatype.AclAction(0).SetACLGID(datatype.ACLID(aclGID)).AddActionFlags(actionFlags)
			if aclAction, find := actionSet[key]; find {
				actionSet[key] = aclAction.AddTagTemplates(tagTemplates)
			} else {
				actionSet[key] = datatype.AclAction(0).SetACLGID(datatype.ACLID(aclGID)).AddActionFlags(actionFlags).AddTagTemplates(tagTemplates)
			}
		}
	}
	aclActions := make([]datatype.AclAction, 0, len(actionSet))
	for _, aclAction := range actionSet {
		aclActions = append(aclActions, aclAction)
	}
	return aclActions
}

func newNpbActions(npbs []*trident.NpbAction) []datatype.NpbAction {
	actions := make([]datatype.NpbAction, 0, len(npbs))
	for _, npb := range npbs {
		tunnelType := uint8(npb.GetTunnelType())
		ip := net.ParseIP(npb.GetTunnelIp())
		if ip == nil && tunnelType != datatype.NPB_TUNNEL_TYPE_PCAP {
			continue
		}
		id := uint32(npb.GetTunnelId() & 0xffffff)
		side := uint8(npb.GetTapSide())
		slice := uint16(npb.GetPayloadSlice())
		aclGid := uint32(0)
		if tunnelType == datatype.NPB_TUNNEL_TYPE_PCAP {
			aclGid = uint32(npb.GetNpbAclGroupId())
		}
		action := datatype.ToNpbAction(ip, aclGid, id, tunnelType, 0, side, slice)
		actions = append(actions, action)
	}
	return actions
}

func newPolicyData(acl *trident.FlowAcl) *policy.Acl {
	return &policy.Acl{
		Id:           acl.GetId(),
		Type:         datatype.TapType(acl.GetTapType()),
		SrcGroups:    datatype.SplitGroup2Int(acl.GetSrcGroupIds()),
		DstGroups:    datatype.SplitGroup2Int(acl.GetDstGroupIds()),
		SrcPortRange: datatype.SplitPort2Int(acl.GetSrcPorts()),
		DstPortRange: datatype.SplitPort2Int(acl.GetDstPorts()),
		Proto:        uint16(acl.GetProtocol() & 0xffff),
		Vlan:         acl.GetVlan() & 0xfff,
		Action:       newAclAction(acl.GetActions()),
		NpbActions:   newNpbActions(acl.GetNpbActions()),
	}
}

// response.GetFlowAcls()
func Convert2AclData(flowAcls []*trident.FlowAcl) []*policy.Acl {
	updateTunnelIpMap(flowAcls)

	policies := make([]*policy.Acl, 0, len(flowAcls))
	for _, acl := range flowAcls {
		if newData := newPolicyData(acl); newData != nil {
			policies = append(policies, newData)
		}
	}

	return policies
}

func newPeerConnection(data *trident.PeerConnection) *datatype.PeerConnection {
	return &datatype.PeerConnection{
		Id:        data.GetId(),
		LocalEpc:  int32(data.GetLocalEpcId() & 0xffff),
		RemoteEpc: int32(data.GetRemoteEpcId() & 0xffff),
	}
}

func Convert2PeerConnections(datas []*trident.PeerConnection) []*datatype.PeerConnection {
	connections := make([]*datatype.PeerConnection, 0, len(datas))
	for _, data := range datas {
		if connection := newPeerConnection(data); connection != nil {
			connections = append(connections, connection)
		}
	}
	return connections
}

func newCidr(data *trident.Cidr) *datatype.Cidr {
	if len(data.GetPrefix()) == 0 {
		return nil
	}
	_, ipNet, err := net.ParseCIDR(data.GetPrefix())
	if err != nil {
		return nil
	}

	epcId := int32(data.GetEpcId())
	if epcId > 0 {
		epcId &= 0xffff
	} else if epcId == 0 {
		epcId = datatype.EPC_FROM_DEEPFLOW
	}

	return &datatype.Cidr{
		IpNet: ipNet,
		EpcId: epcId,
		Type:  uint8(data.GetType()),
	}
}

func Convert2Cidrs(datas []*trident.Cidr) []*datatype.Cidr {
	cidrs := make([]*datatype.Cidr, 0, len(datas))
	for _, data := range datas {
		if cidr := newCidr(data); cidr != nil {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}
