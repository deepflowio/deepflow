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
	SrcPortRange      []PortRange // 0仅表示采集端口0
	DstPortRange      []PortRange // 0仅表示采集端口0
	SrcPorts          []uint16    // 0仅表示采集端口0
	DstPorts          []uint16    // 0仅表示采集端口0
	Proto             uint16      // 256表示全采集, 0表示采集采集协议0
	Vlan              uint32
	Action            []AclAction
	NpbActions        []NpbAction
	AllMatched        []MatchedField
	AllMatchedMask    []MatchedField // MatchedMask对应的位为0，表示对应Matched的位为*，0或1都匹配该策略
	AllMatched6       []MatchedField6
	AllMatched6Mask   []MatchedField6 // MatchedMask对应的位为0，表示对应Matched的位为*，0或1都匹配该策略
	policy            PolicyRawData
}

const (
	PROTO_ALL = 256
)

func (a *Acl) InitPolicy() {
	a.policy.ACLID = a.Id
	a.policy.AclActions = a.Action
	a.policy.NpbActions = a.NpbActions
}

func (a *Acl) Reset() {
	a.SrcPorts = a.SrcPorts[:0]
	a.DstPorts = a.DstPorts[:0]
	a.SrcGroupRelations = a.SrcGroupRelations[:0]
	a.DstGroupRelations = a.DstGroupRelations[:0]
	a.AllMatched = a.AllMatched[:0]
	a.AllMatchedMask = a.AllMatchedMask[:0]
	a.AllMatched6 = a.AllMatched6[:0]
	a.AllMatched6Mask = a.AllMatched6Mask[:0]
}

func (a *Acl) getPortRange(rawPorts []uint16) []PortRange {
	ranges := make([]PortRange, 0, 2)

	min, max := uint16(0), uint16(0)
	for index, port := range rawPorts {
		if index == 0 {
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

func (a *Acl) generatePortSegment() ([]portSegment, []portSegment) {
	srcSegment := make([]portSegment, 0, 2)
	dstSegment := make([]portSegment, 0, 2)
	for _, ports := range a.getPortRange(a.SrcPorts) {
		srcSegment = append(srcSegment, newPortSegments(ports)...)
	}
	for _, ports := range a.getPortRange(a.DstPorts) {
		dstSegment = append(dstSegment, newPortSegments(ports)...)
	}
	if len(srcSegment) == 0 {
		srcSegment = append(srcSegment, allPortSegment)
	}
	if len(dstSegment) == 0 {
		dstSegment = append(dstSegment, allPortSegment)
	}
	return srcSegment, dstSegment
}

func (a *Acl) generateMatchedField(srcMac, dstMac uint64, srcIps, dstIps ipSegment, srcPorts, dstPorts []portSegment) {
	for _, srcPort := range srcPorts {
		for _, dstPort := range dstPorts {
			match, mask := MatchedField{}, MatchedField{}

			match.Set(MATCHED_TAP_TYPE, uint64(a.Type))
			match.Set(MATCHED_VLAN, uint64(a.Vlan))
			match.Set(MATCHED_SRC_MAC, srcMac)
			match.Set(MATCHED_DST_MAC, dstMac)
			match.Set(MATCHED_SRC_IP, uint64(srcIps.getIp()))
			match.Set(MATCHED_SRC_EPC, uint64(srcIps.getEpcId()))
			match.Set(MATCHED_DST_IP, uint64(dstIps.getIp()))
			match.Set(MATCHED_DST_EPC, uint64(dstIps.getEpcId()))
			match.Set(MATCHED_SRC_PORT, uint64(srcPort.port))
			match.Set(MATCHED_DST_PORT, uint64(dstPort.port))

			mask.SetMask(MATCHED_TAP_TYPE, uint64(a.Type))
			mask.SetMask(MATCHED_VLAN, uint64(a.Vlan))
			mask.SetMask(MATCHED_SRC_MAC, srcMac)
			mask.SetMask(MATCHED_DST_MAC, dstMac)
			mask.Set(MATCHED_SRC_IP, uint64(srcIps.getMask()))
			mask.SetMask(MATCHED_SRC_EPC, uint64(srcIps.getEpcId()))
			mask.Set(MATCHED_DST_IP, uint64(dstIps.getMask()))
			mask.SetMask(MATCHED_DST_EPC, uint64(dstIps.getEpcId()))
			mask.Set(MATCHED_SRC_PORT, uint64(srcPort.mask))
			mask.Set(MATCHED_DST_PORT, uint64(dstPort.mask))

			if a.Proto == PROTO_ALL {
				match.Set(MATCHED_PROTO, 0)
				mask.Set(MATCHED_PROTO, 0)
			} else {
				match.Set(MATCHED_PROTO, uint64(a.Proto))
				mask.SetMask(MATCHED_PROTO, uint64(0xff))
			}

			a.AllMatched = append(a.AllMatched, match)
			a.AllMatchedMask = append(a.AllMatchedMask, mask)
		}
	}
}

func (a *Acl) generateMatchedField6(srcMac, dstMac uint64, srcIps, dstIps ipSegment, srcPorts, dstPorts []portSegment) {
	for _, srcPort := range srcPorts {
		for _, dstPort := range dstPorts {
			match, mask := MatchedField6{}, MatchedField6{}
			match.Set(MATCHED6_TAP_TYPE, uint64(a.Type))
			match.Set(MATCHED6_PROTO, uint64(a.Proto))
			match.Set(MATCHED6_VLAN, uint64(a.Vlan))
			match.Set(MATCHED6_SRC_MAC, srcMac)
			match.Set(MATCHED6_DST_MAC, dstMac)
			ip0, ip1 := srcIps.getIp6()
			match.Set(MATCHED6_SRC_IP0, ip0)
			match.Set(MATCHED6_SRC_IP1, ip1)
			match.Set(MATCHED6_SRC_EPC, uint64(srcIps.getEpcId()))
			ip0, ip1 = dstIps.getIp6()
			match.Set(MATCHED6_DST_IP0, ip0)
			match.Set(MATCHED6_DST_IP1, ip1)
			match.Set(MATCHED6_DST_EPC, uint64(dstIps.getEpcId()))
			match.Set(MATCHED6_SRC_PORT, uint64(srcPort.port))
			match.Set(MATCHED6_DST_PORT, uint64(dstPort.port))

			mask.SetMask(MATCHED6_TAP_TYPE, uint64(a.Type))
			mask.SetMask(MATCHED6_PROTO, uint64(a.Proto))
			mask.SetMask(MATCHED6_VLAN, uint64(a.Vlan))
			mask.SetMask(MATCHED6_SRC_MAC, srcMac)
			mask.SetMask(MATCHED6_DST_MAC, dstMac)
			mask0, mask1 := srcIps.getMask6()
			mask.Set(MATCHED6_SRC_IP0, mask0)
			mask.Set(MATCHED6_SRC_IP1, mask1)
			mask.SetMask(MATCHED6_SRC_EPC, uint64(srcIps.getEpcId()))
			mask0, mask1 = dstIps.getMask6()
			mask.Set(MATCHED6_DST_IP0, mask0)
			mask.Set(MATCHED6_DST_IP1, mask1)
			mask.SetMask(MATCHED6_DST_EPC, uint64(dstIps.getEpcId()))
			mask.Set(MATCHED6_SRC_PORT, uint64(srcPort.mask))
			mask.Set(MATCHED6_DST_PORT, uint64(dstPort.mask))

			if a.Proto == PROTO_ALL {
				match.Set(MATCHED6_PROTO, 0)
				mask.SetMask(MATCHED6_PROTO, 0)
			} else {
				match.Set(MATCHED6_PROTO, uint64(a.Proto))
				mask.SetMask(MATCHED6_PROTO, uint64(0xff))
			}

			a.AllMatched6Mask = append(a.AllMatched6Mask, mask)
			a.AllMatched6 = append(a.AllMatched6, match)
		}
	}
}

func (a *Acl) generateMatched(srcMac, dstMac []uint64, srcIps, dstIps []ipSegment) {
	srcPorts, dstPorts := a.generatePortSegment()
	for _, srcMac := range srcMac {
		for _, dstMac := range dstMac {
			// mac + mac分别在ipv4和ipv6表中，避免IPv6需要查询两次
			a.generateMatchedField(srcMac, dstMac, emptyIpSegment, emptyIpSegment, srcPorts, dstPorts)
			a.generateMatchedField6(srcMac, dstMac, emptyIpSegment, emptyIpSegment, srcPorts, dstPorts)
		}
		for _, dstIp := range dstIps {
			if dstIp.isIpv6() {
				a.generateMatchedField6(srcMac, 0, emptyIpSegment, dstIp, srcPorts, dstPorts)
			} else {
				a.generateMatchedField(srcMac, 0, emptyIpSegment, dstIp, srcPorts, dstPorts)
			}
		}
	}
	for _, srcIp := range srcIps {
		for _, dstMac := range dstMac {
			if srcIp.isIpv6() {
				a.generateMatchedField6(0, dstMac, srcIp, emptyIpSegment, srcPorts, dstPorts)
			} else {
				a.generateMatchedField(0, dstMac, srcIp, emptyIpSegment, srcPorts, dstPorts)
			}
		}
		for _, dstIp := range dstIps {
			if srcIp.isIpv6() != dstIp.isIpv6() {
				continue
			}

			if srcIp.isIpv6() {
				// ipv6 + ipv6
				a.generateMatchedField6(0, 0, srcIp, dstIp, srcPorts, dstPorts)
			} else {
				// ipv4 + ipv4
				a.generateMatchedField(0, 0, srcIp, dstIp, srcPorts, dstPorts)
			}
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
