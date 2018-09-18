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

var ActionMap = [...]datatype.ActionType{
	trident.Action_PACKECT_COUNTER:     datatype.ACTION_PACKET_STAT,
	trident.Action_FLOW_COUNTER:        datatype.ACTION_FLOW_STAT,
	trident.Action_FLOW_STORAGE:        datatype.ACTION_FLOW_STORE,
	trident.Action_TCP_PERFORMANCE:     datatype.ACTION_PERFORMANCE,
	trident.Action_PCAP:                datatype.ACTION_PCAP,
	trident.Action_MISC:                datatype.ACTION_MISC,
	trident.Action_POLICY:              datatype.ACTION_POLICY,
	trident.Action_PACKECT_COUNTER_PUB: datatype.ACTION_PACKECT_COUNTER_PUB,
	trident.Action_FLOW_COUNTER_PUB:    datatype.ACTION_FLOW_COUNTER_PUB,
	trident.Action_TCP_PERFORMANCE_PUB: datatype.ACTION_TCP_PERFORMANCE_PUB,
}

func newPlatformData(vifData *trident.Interface) *datatype.PlatformData {
	macInt := uint64(0)
	if mac, err := net.ParseMAC(vifData.GetMac()); err == nil {
		macInt = Mac2Uint64(mac)
	}

	hostIp := uint32(0)
	ip := net.ParseIP(vifData.GetLaunchServer())
	if ip != nil {
		hostIp = IpToUint32(ip)
	}

	ips := make([]*datatype.IpNet, 0, 1024)
	for _, ipResource := range vifData.IpResources {
		fixIp := net.ParseIP(ipResource.GetIp())
		if fixIp == nil {
			continue
		}
		netmask := ipResource.GetMasklen()
		if netmask == 0 || netmask > datatype.MAX_MASK_LEN || netmask < datatype.MIN_MASK_LEN {
			netmask = datatype.MAX_MASK_LEN
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

func Convert2PlatformData(response *trident.SyncResponse) []*datatype.PlatformData {
	interfaces := response.GetPlatformData().GetInterfaces()
	platformDatas := make([]*datatype.PlatformData, 0, len(interfaces))
	for _, data := range interfaces {
		if newData := newPlatformData(data); newData != nil {
			platformDatas = append(platformDatas, newData)
		}
	}
	return platformDatas
}

func newIpGroupData(ipGroup *trident.Group) *policy.IpGroupData {
	if ipGroup == nil || ipGroup.GetIps() == nil {
		return nil
	}
	return &policy.IpGroupData{
		Id:    ipGroup.GetId(),
		EpcId: int32(ipGroup.GetEpcId()),
		Type:  uint8(ipGroup.GetType()),
		Ips:   ipGroup.GetIps(),
	}
}

func Convert2IpGroupdata(response *trident.SyncResponse) []*policy.IpGroupData {
	ipGroups := response.GetPlatformData().GetIpGroups()
	ipGroupDatas := make([]*policy.IpGroupData, 0, len(ipGroups))
	for _, group := range ipGroups {
		if newData := newIpGroupData(group); newData != nil {
			ipGroupDatas = append(ipGroupDatas, newData)
		}
	}

	return ipGroupDatas
}

func splitGroup2Int(src string) map[uint32]uint32 {
	splitSrcGroups := strings.Split(src, ",")
	groups := make(map[uint32]uint32)
	for _, group := range splitSrcGroups {
		groupInt, err := strconv.Atoi(group)
		if err == nil {
			groups[uint32(groupInt)] = uint32(groupInt)
		}
	}

	return groups
}

func splitPort2Int(src string) map[uint16]uint16 {
	splitSrcPorts := strings.Split(src, "-")
	ports := make(map[uint16]uint16)
	if len(splitSrcPorts) < 2 {
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
	for i := portRange[0]; i <= portRange[1]; i++ {
		ports[i] = i
		if i == 0xffff {
			break
		}
	}

	return ports
}

func newPolicyInfo(policies []*trident.Policy) []datatype.PolicyInfo {
	policyInfos := make([]datatype.PolicyInfo, 0, len(policies))
	for _, value := range policies {
		info := datatype.PolicyInfo{
			Id:   value.GetId(),
			Type: datatype.PolicyType(value.GetType()),
		}
		policyInfos = append(policyInfos, info)
	}

	return policyInfos
}

func convert2ActionType(action trident.Action) datatype.ActionType {
	if action := ActionMap[action]; action != 0 {
		return action
	}
	return datatype.ActionType(0)
}

func newAclAction(aclId uint32, actions []*trident.FlowAction) []*datatype.AclAction {
	aclActions := make([]*datatype.AclAction, 0, len(actions))
	for _, action := range actions {
		if policyType := convert2ActionType(action.GetAction()); policyType != 0 {
			aclAction := &datatype.AclAction{
				AclId:       aclId,
				Type:        policyType,
				Policy:      newPolicyInfo(action.GetPolicies()),
				TagTemplate: action.GetTagTemplate(),
			}
			aclActions = append(aclActions, aclAction)
		}
	}

	return aclActions
}

func newPolicyData(acl *trident.FlowAcl) *policy.Acl {
	return &policy.Acl{
		Id:        acl.GetId(),
		Type:      datatype.TapType(acl.GetTapType()),
		TapId:     acl.GetTapId(),
		SrcGroups: splitGroup2Int(acl.GetSrcGroupIds()),
		DstGroups: splitGroup2Int(acl.GetDstGroupIds()),
		DstPorts:  splitPort2Int(acl.GetDstPorts()),
		Proto:     uint8(acl.GetProtocol()),
		Vlan:      acl.GetVlan(),
		Action:    newAclAction(acl.GetId(), acl.GetActions()),
	}
}

func Convert2AclData(response *trident.SyncResponse) []*policy.Acl {
	flowAcls := response.GetFlowAcls()
	policies := make([]*policy.Acl, 0, len(flowAcls))
	for _, acl := range flowAcls {
		if newData := newPolicyData(acl); newData != nil {
			policies = append(policies, newData)
		}
	}

	return policies
}
