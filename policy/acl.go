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
	AllMatcheds       []MatchedField
	MatchedMask       MatchedField // MatchedMask对应的位为0，表示对应Matched的位为*，0或1都匹配该策略
}

func (a *Acl) generateMatchedField() {
	matches := make([]MatchedField, 0, len(a.SrcGroupRelations)*len(a.DstGroupRelations)*len(a.SrcPortRange)*len(a.DstPortRange))
	// FIXME: 循化嵌套太多
	for _, srcGroup := range a.SrcGroupRelations {
		for _, dstGroup := range a.DstGroupRelations {
			for _, srcPort := range a.SrcPortRange {
				for _, dstPort := range a.DstPortRange {
					match := MatchedField{}
					match.Set(MATCHED_TAP_TYPE, uint16(a.Type))
					match.Set(MATCHED_PROTO, uint16(a.Proto))
					match.Set(MATCHED_VLAN, uint16(a.Vlan))
					match.Set(MATCHED_SRC_GROUP, srcGroup)
					match.Set(MATCHED_DST_GROUP, dstGroup)
					match.Set(MATCHED_SRC_PORT, srcPort.Min())
					match.Set(MATCHED_DST_PORT, dstPort.Min())
					matches = append(matches, match)
				}
			}
		}
	}
	a.AllMatcheds = matches
}

func (a *Acl) generateMatchedMask() {
	// 字段非0，对应位值为其掩码
	a.MatchedMask.SetMask(MATCHED_TAP_TYPE, uint16(a.Type))
	a.MatchedMask.SetMask(MATCHED_PROTO, uint16(a.Proto))
	a.MatchedMask.SetMask(MATCHED_VLAN, uint16(a.Vlan))
	// 掩码只区分是否全采集，所以使用切片中的一个
	a.MatchedMask.SetMask(MATCHED_SRC_GROUP, a.SrcGroupRelations[0])
	a.MatchedMask.SetMask(MATCHED_DST_GROUP, a.DstGroupRelations[0])
	a.MatchedMask.SetMask(MATCHED_SRC_PORT, a.SrcPorts[0])
	a.MatchedMask.SetMask(MATCHED_DST_PORT, a.DstPorts[0])
}

func (a *Acl) generateMatched() {
	a.generateMatchedField()
	a.generateMatchedMask()
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
