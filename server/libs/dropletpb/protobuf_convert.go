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

package dropletpb

import (
	"net"
	"strings"

	"github.com/deepflowio/deepflow/message/trident"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/policy"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("dropletpb")

func newPlatformData(vifData *trident.Interface, platform *datatype.PlatformData, ipNets []datatype.IpNet) {
	macInt := vifData.GetMac()
	ipNetsCount := 0
	for _, ipResource := range vifData.IpResources {
		fixIp := ParserStringIp(ipResource.GetIp())
		if fixIp == nil {
			log.Warningf("Platform(%v) has invalid ip-resource(%s).", vifData, ipResource.GetIp())
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

		ipNets[ipNetsCount].RawIp = fixIp
		ipNets[ipNetsCount].Netmask = netmask
		ipNets[ipNetsCount].SubnetId = ipResource.GetSubnetId()
		ipNetsCount++
	}

	epcId := int32(vifData.GetEpcId())
	if epcId > 0 {
		epcId &= 0xffff
	} else if epcId == 0 {
		epcId = datatype.EPC_FROM_DEEPFLOW
	}

	platform.Id = vifData.GetId()
	platform.Mac = macInt
	if ipNetsCount > 0 {
		platform.Ips = ipNets[:ipNetsCount]
	}
	platform.EpcId = epcId
	platform.IfType = uint8(vifData.GetIfType())
	platform.IsVIPInterface = vifData.GetIsVipInterface()
	platform.RegionId = vifData.GetRegionId()
	platform.PodClusterId = vifData.GetPodClusterId()
	platform.PodNodeId = vifData.GetPodNodeId()
	platform.DeviceType = uint8(vifData.GetDeviceType())
}

// response.GetPlatformData().GetInterfaces()
func Convert2PlatformData(interfaces []*trident.Interface) []datatype.PlatformData {
	// 因为这里的数据在用户场景比较多，对GC影响比较大，这里内存一次申请
	platformDatas := make([]datatype.PlatformData, len(interfaces))

	ipNetsCount := 0
	for _, data := range interfaces {
		ipNetsCount += len(data.IpResources)
	}
	ipNets := make([]datatype.IpNet, ipNetsCount)

	ipNetsIndex := 0
	for i, data := range interfaces {
		newPlatformData(data, &platformDatas[i], ipNets[ipNetsIndex:])
		ipNetsIndex += len(data.IpResources)
	}
	return platformDatas
}

func Convert2Vips(datas []string) ([]net.IP, []net.IP) {
	ipv4s := make([]net.IP, 0, len(datas))
	ipv6s := make([]net.IP, 0, len(datas))
	for _, data := range datas {
		ip := net.ParseIP(data)
		if ip == nil {
			log.Warningf("Vip has invalid ip(%s).", data)
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
		log.Warningf("IpGroup(%v) is invalid, ips and ip-range is nil.", ipGroup)
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
				log.Warningf("IpGroup(%v) has invalid ip-range(%s).", ipGroup, ipRange)
				continue
			}
			startIp := ParserStringIp(ipPeers[0])
			endIp := ParserStringIp(ipPeers[1])
			if startIp == nil || endIp == nil {
				log.Warningf("IpGroup(%v) has invalid ip-range(%s).", ipGroup, ipRange)
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
			if ip == nil ||
				tunnelType == datatype.NPB_TUNNEL_TYPE_PCAP ||
				tunnelType == datatype.NPB_TUNNEL_TYPE_NPB_DROP {
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
		log.Warningf("Cidr(%v) is invalid.", data)
		return nil
	}
	_, ipNet, err := net.ParseCIDR(data.GetPrefix())
	if err != nil {
		log.Warningf("Cidr(%v) has invalid prefix(%s).", data, data.GetPrefix())
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
		RegionId: data.GetRegionId(),
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
