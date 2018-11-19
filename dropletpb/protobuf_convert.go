package dropletpb

import (
	"net"
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/message/trident"
)

var maskLenToNetmask [datatype.MASK_LEN_NUM]uint32

func newPlatformData(vifData *trident.Interface) *datatype.PlatformData {
	macInt := uint64(0)
	if mac, err := net.ParseMAC(vifData.GetMac()); err == nil {
		macInt = Mac2Uint64(mac)
	}

	hostIp := uint32(0)
	ip := ParserStringIpV4(vifData.GetLaunchServer())
	if ip != nil {
		hostIp = IpToUint32(ip)
	}

	ips := make([]*datatype.IpNet, 0, 1024)
	for _, ipResource := range vifData.IpResources {
		fixIp := ParserStringIpV4(ipResource.GetIp())
		if fixIp == nil {
			continue
		}
		netmask := ipResource.GetMasklen()
		if netmask > datatype.MAX_MASK_LEN {
			netmask = datatype.MAX_MASK_LEN
		} else if netmask < datatype.MIN_MASK_LEN {
			netmask = datatype.MIN_MASK_LEN
		}
		ipinfo := &datatype.IpNet{
			Ip:       IpToUint32(fixIp),
			Netmask:  netmask,
			SubnetId: ipResource.GetSubnetId(),
		}
		ips = append(ips, ipinfo)
	}
	return &datatype.PlatformData{
		Mac:        macInt,
		Ips:        ips,
		EpcId:      int32(vifData.GetEpcId()),
		DeviceType: vifData.GetDeviceType(),
		DeviceId:   vifData.GetDeviceId(),
		IfIndex:    vifData.GetIfIndex(),
		IfType:     vifData.GetIfType(),
		HostIp:     hostIp,
		GroupIds:   vifData.GetGroupIds(),
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

func ipRangeConvert2CIDR(startIp, endIp net.IP) []net.IPNet {
	start := IpToUint32(startIp)
	end := IpToUint32(endIp)
	var ips []net.IPNet
	for start <= end {
		maskLen := getFirstMask(start, end)
		ip := IpFromUint32(start)
		ipMask := net.CIDRMask(int(maskLen), datatype.MAX_MASK_LEN)
		ips = append(ips, net.IPNet{IP: ip, Mask: ipMask})
		lastIp := getLastIp(start, maskLen)
		if lastIp == datatype.MAX_NETMASK {
			break
		}
		start += 1 << uint32(datatype.MAX_MASK_LEN-maskLen)
	}
	return ips
}

func getFirstMask(start, end uint32) uint8 {
	maxLen := datatype.MAX_MASK_LEN
	for ; maxLen > datatype.MIN_MASK_LEN; maxLen-- {
		if start&(1<<uint32(datatype.MAX_MASK_LEN-maxLen)) != 0 {
			// maxLen继续减少将会使得start不是所在网段的第一个IP
			break
		}
		if start+^maskLenToNetmask[maxLen] >= end || start+^maskLenToNetmask[maxLen-1] > end {
			// maxLen继续减少将会使得网段包含end之后的IP
			break
		}
	}
	return uint8(maxLen)
}

func getLastIp(ip uint32, mask uint8) uint32 {
	ip += ^maskLenToNetmask[mask]
	return ip
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
			startIp := ParserStringIpV4(strings.Split(ipRange, "-")[0])
			endIp := ParserStringIpV4(strings.Split(ipRange, "-")[1])
			if startIp == nil || endIp == nil {
				continue
			}
			for _, ip := range ipRangeConvert2CIDR(startIp, endIp) {
				ips = append(ips, ip.String())
			}
		}
	}
	return &policy.IpGroupData{
		Id:    ipGroup.GetId(),
		EpcId: int32(ipGroup.GetEpcId()),
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

func splitGroup2Int(src string) []uint32 {
	splitSrcGroups := strings.Split(src, ",")
	groups := make([]uint32, 0, 8)
	for _, group := range splitSrcGroups {
		groupInt, err := strconv.Atoi(group)
		if err == nil {
			groups = append(groups, uint32(groupInt))
		}
	}

	return groups
}

func getPorts(src string) []uint16 {
	splitSrcPorts := strings.Split(src, "-")
	ports := make([]uint16, 0, 8)
	if len(splitSrcPorts) < 2 {
		portInt, err := strconv.Atoi(src)
		if err == nil {
			ports = append(ports, uint16(portInt))
		}
		return ports
	}
	portRange := [2]uint16{0, 0}
	for index, port := range splitSrcPorts {
		if index == 2 {
			break
		}
		portInt, err := strconv.Atoi(port)
		if err == nil {
			portRange[index] = uint16(portInt)
		}
	}

	if portRange[1] > portRange[0] && portRange[1]-portRange[0] >= 65534 {
		return ports
	}

	for i := portRange[0]; i <= portRange[1]; i++ {
		ports = append(ports, uint16(i))
		if i == 0xffff {
			break
		}
	}
	return ports
}

func splitPort2Int(src string) []uint16 {
	ports := make([]uint16, 0, 8)
	splitSrcPorts := strings.Split(src, ",")
	for _, srcPorts := range splitSrcPorts {
		ports = append(ports, getPorts(srcPorts)...)
	}
	return ports
}

func newAclAction(aclId datatype.ACLID, actions []*trident.FlowAction) []datatype.AclAction {
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
		ip := net.ParseIP(npb.GetTunnelIp())
		if ip == nil {
			continue
		}
		id := uint8(npb.GetTunnelId())
		side := uint8(npb.GetTapSide())
		slice := uint16(npb.GetPayloadSlice())
		action := datatype.ToNpbAction(IpToUint32(ip.To4()), id, 0, side, slice)
		actions = append(actions, action)
	}
	return actions
}

func newPolicyData(acl *trident.FlowAcl) *policy.Acl {
	return &policy.Acl{
		Id:         datatype.ACLID(acl.GetId()),
		Type:       datatype.TapType(acl.GetTapType()),
		TapId:      acl.GetTapId(),
		SrcGroups:  splitGroup2Int(acl.GetSrcGroupIds()),
		DstGroups:  splitGroup2Int(acl.GetDstGroupIds()),
		SrcPorts:   splitPort2Int(acl.GetSrcPorts()),
		DstPorts:   splitPort2Int(acl.GetDstPorts()),
		Proto:      uint8(acl.GetProtocol()),
		Vlan:       acl.GetVlan(),
		Action:     newAclAction(datatype.ACLID(acl.GetId()), acl.GetActions()),
		NpbActions: newNpbActions(acl.GetNpbActions()),
	}
}

// response.GetFlowAcls()
func Convert2AclData(flowAcls []*trident.FlowAcl) []*policy.Acl {
	policies := make([]*policy.Acl, 0, len(flowAcls))
	for _, acl := range flowAcls {
		if newData := newPolicyData(acl); newData != nil {
			policies = append(policies, newData)
		}
	}

	return policies
}

func init() {
	// fill maskLenToNetmask with {0x00000000, 0x80000000, 0xC0000000, ...}
	mask := uint32(datatype.MAX_NETMASK)
	for i := datatype.MIN_MASK_LEN; i <= datatype.MAX_MASK_LEN; i++ {
		maskLenToNetmask[i] = ^mask
		mask >>= 1
	}
}
