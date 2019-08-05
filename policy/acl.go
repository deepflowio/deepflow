package policy

import (
	"fmt"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type Acl struct {
	Id                ACLID
	Type              TapType
	TapId             uint32
	SrcGroups         []uint32
	DstGroups         []uint32
	SrcGroupRelations []uint16
	DstGroupRelations []uint16
	SrcPortRange      []PortRange
	DstPortRange      []PortRange
	SrcPorts          []uint16
	DstPorts          []uint16
	Proto             uint8
	Vlan              uint32
	Action            []AclAction
	NpbActions        []NpbAction
	AllMatched        []MatchedField
	AllMatchedMask    []MatchedField // MatchedMask对应的位为0，表示对应Matched的位为*，0或1都匹配该策略
	policy            PolicyRawData
}

func (a *Acl) InitPolicy() {
	a.policy.ACLID = a.Id
	a.policy.AclActions = a.Action
	a.policy.NpbActions = a.NpbActions
}

func (a *Acl) getPortRange(rawPorts []uint16) []PortRange {
	ranges := make([]PortRange, 0, 2)

	min, max := uint16(0), uint16(0)
	for index, port := range rawPorts {
		if min == 0 {
			min = port
			max = port
			if len(rawPorts) == index+1 {
				ranges = append(ranges, NewPortRange(min, max))
			}
			continue
		}

		if port == max+1 {
			max = port
		} else {
			ranges = append(ranges, NewPortRange(min, max))
			min = port
			max = port
		}

		if len(rawPorts) == index+1 {
			ranges = append(ranges, NewPortRange(min, max))
		}
	}
	return ranges
}

func (a *Acl) generateMatchedField(srcMac, dstMac uint32, srcIps, dstIps ipSegment, ethType int) {
	srcSegment := make([]portSegment, 0, 2)
	dstSegment := make([]portSegment, 0, 2)
	for _, ports := range a.getPortRange(a.SrcPorts) {
		srcSegment = append(srcSegment, newPortSegments(ports)...)
	}
	for _, ports := range a.getPortRange(a.DstPorts) {
		dstSegment = append(dstSegment, newPortSegments(ports)...)
	}
	if len(srcSegment) == 0 {
		srcSegment = append(srcSegment, emptyPortSegment)
	}
	if len(dstSegment) == 0 {
		dstSegment = append(dstSegment, emptyPortSegment)
	}

	for _, srcPort := range srcSegment {
		for _, dstPort := range dstSegment {
			match := MatchedField{}
			match.Set(MATCHED_ETH_TYPE, uint32(ethType))
			match.Set(MATCHED_TAP_TYPE, uint32(a.Type))
			match.Set(MATCHED_PROTO, uint32(a.Proto))
			match.Set(MATCHED_VLAN, uint32(a.Vlan))
			match.Set(MATCHED_SRC_MAC, srcMac)
			match.Set(MATCHED_DST_MAC, dstMac)
			match.Set(MATCHED_SRC_IP, srcIps.getIp())
			match.Set(MATCHED_SRC_EPC, uint32(srcIps.getEpcId()))
			match.Set(MATCHED_DST_IP, dstIps.getIp())
			match.Set(MATCHED_DST_EPC, uint32(dstIps.getEpcId()))
			match.Set(MATCHED_SRC_PORT, uint32(srcPort.port))
			match.Set(MATCHED_DST_PORT, uint32(dstPort.port))
			a.AllMatched = append(a.AllMatched, match)

			mask := MatchedField{}
			mask.SetMask(MATCHED_ETH_TYPE, uint32(ethType))
			mask.SetMask(MATCHED_TAP_TYPE, uint32(a.Type))
			mask.SetMask(MATCHED_PROTO, uint32(a.Proto))
			mask.SetMask(MATCHED_VLAN, uint32(a.Vlan))
			mask.SetMask(MATCHED_SRC_MAC, srcMac)
			mask.SetMask(MATCHED_DST_MAC, dstMac)
			mask.Set(MATCHED_SRC_IP, srcIps.getMask())
			mask.SetMask(MATCHED_SRC_EPC, uint32(srcIps.getEpcId()))
			mask.Set(MATCHED_DST_IP, dstIps.getMask())
			mask.SetMask(MATCHED_DST_EPC, uint32(dstIps.getEpcId()))
			mask.Set(MATCHED_SRC_PORT, uint32(srcPort.mask))
			mask.Set(MATCHED_DST_PORT, uint32(dstPort.mask))
			a.AllMatchedMask = append(a.AllMatchedMask, mask)
		}
	}
}

func (a *Acl) generateMatched(srcMac, dstMac []uint32, srcIps, dstIps []ipSegment) {
	for _, srcMac := range srcMac {
		for _, dstMac := range dstMac {
			a.generateMatchedField(srcMac, dstMac, emptyIpSegment, emptyIpSegment, ETH_TYPE_ALL)
		}
		for _, dstIp := range dstIps {
			a.generateMatchedField(srcMac, 0, emptyIpSegment, dstIp, ETH_TYPE_IPV4)
		}
	}
	for _, srcIp := range srcIps {
		for _, dstMac := range dstMac {
			a.generateMatchedField(0, dstMac, srcIp, emptyIpSegment, ETH_TYPE_IPV4)
		}
		for _, dstIp := range dstIps {
			a.generateMatchedField(0, 0, srcIp, dstIp, ETH_TYPE_IPV4)
		}
	}
}

func (a *Acl) getPorts(rawPorts []uint16) string {
	// IN: rawPorts: 1,3,4,5,7,10,11,12,15,17
	// OUT: ports: "1,3-5,7,10-12,15,17"
	end := uint16(0)
	hasDash := false
	ports := ""
	for index, port := range rawPorts {
		if index == 0 {
			ports += fmt.Sprintf("%d", port)
			end = port
			continue
		}

		if port == end+1 {
			end = port
			hasDash = true
			if index == len(rawPorts)-1 {
				ports += fmt.Sprintf("-%d", port)
			}
		} else {
			if hasDash {
				ports += fmt.Sprintf("-%d", end)
				hasDash = false
			}
			ports += fmt.Sprintf(",%d", port)
			end = port
		}
	}
	return ports
}

func (a *Acl) String() string {
	return fmt.Sprintf("Id:%v Type:%v TapId:%v SrcGroups:%v DstGroups:%v SrcPortRange:[%v] SrcPorts:[%s] DstPortRange:[%v] DstPorts:[%s] Proto:%v Vlan:%v Action:%v NpbActions:%s",
		a.Id, a.Type, a.TapId, a.SrcGroups, a.DstGroups, a.SrcPortRange, a.getPorts(a.SrcPorts), a.DstPortRange, a.getPorts(a.DstPorts), a.Proto, a.Vlan, a.Action, a.NpbActions)
}
