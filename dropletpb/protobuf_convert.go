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
		Id:             vifData.GetId(),
		Mac:            macInt,
		Ips:            ips,
		EpcId:          epcId,
		IfType:         uint8(vifData.GetIfType()),
		IsVIPInterface: vifData.GetIsVipInterface(),
		RegionId:       vifData.GetRegionId(),
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

func Convert2Vips(datas []string) ([]net.IP, []net.IP) {
	ipv4s := make([]net.IP, 0, len(datas))
	ipv6s := make([]net.IP, 0, len(datas))
	for _, data := range datas {
		ip := net.ParseIP(data)
		if ip == nil {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4s = append(ipv4s, ipv4)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv4s, ipv6s
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

	return &policy.IpGroupData{
		Id:    ipGroup.GetId() & 0xffff,
		EpcId: int32(ipGroup.GetEpcId() & 0xffff),
		Type:  uint8(ipGroup.GetType()),
		Ips:   ips,
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
	aclGids := make([]uint16, 0, len(flowAcls))
	ipIds := make([]uint16, 0, len(flowAcls))
	ips := make([]net.IP, 0, len(flowAcls))

	for _, acl := range flowAcls {
		for _, npb := range acl.GetNpbActions() {
			tunnelType := uint8(npb.GetTunnelType())
			ip := net.ParseIP(npb.GetTunnelIp())
			if ip == nil || tunnelType == datatype.NPB_TUNNEL_TYPE_PCAP {
				continue
			}
			aclGid := uint16(npb.GetNpbAclGroupId())
			ipId := uint16(npb.GetTunnelIpId() & 0xffff)

			if ip.To4() != nil {
				ip = ip.To4()
			}
			aclGids = append(aclGids, aclGid)
			ipIds = append(ipIds, ipId)
			ips = append(ips, ip)
		}
	}
	datatype.UpdateTunnelMaps(aclGids, ipIds, ips)
}

func newNpbActions(npbs []*trident.NpbAction) []datatype.NpbActions {
	actions := make([]datatype.NpbActions, 0, len(npbs))
	for _, npb := range npbs {
		tunnelType := uint8(npb.GetTunnelType())
		ip := net.ParseIP(npb.GetTunnelIp())
		if ip == nil && tunnelType != datatype.NPB_TUNNEL_TYPE_PCAP {
			continue
		}
		id := uint32(npb.GetTunnelId() & 0xffffff)
		side := uint8(npb.GetTapSide())
		slice := uint16(npb.GetPayloadSlice())
		aclGid := uint32(npb.GetNpbAclGroupId() & 0xffff)
		action := datatype.ToNpbActions(aclGid, id, tunnelType, side, slice)
		actions = append(actions, action)
	}
	return actions
}

func newPolicyData(acl *trident.FlowAcl) *policy.Acl {
	return &policy.Acl{
		Id:           acl.GetId(),
		TapType:      datatype.TapType(acl.GetTapType() & 0xff),
		SrcGroups:    datatype.SplitGroup2Int(acl.GetSrcGroupIds()),
		DstGroups:    datatype.SplitGroup2Int(acl.GetDstGroupIds()),
		SrcPortRange: datatype.SplitPort2Int(acl.GetSrcPorts()),
		DstPortRange: datatype.SplitPort2Int(acl.GetDstPorts()),
		Proto:        uint16(acl.GetProtocol() & 0xffff),
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
		IpNet:    ipNet,
		EpcId:    epcId,
		Type:     uint8(data.GetType()),
		TunnelId: data.GetTunnelId(),
		IsVIP:    data.GetIsVip(),
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
