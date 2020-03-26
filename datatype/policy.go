package datatype

import (
	"fmt"
	"math"
	"net"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

var (
	INVALID_POLICY_DATA = new(PolicyData)

	// 通过aclGid分别查询tunnelIp或tunnelIpId
	tunnelIpMap   = [math.MaxUint16 + 1]net.IP{}
	tunnelIpIdMap = [math.MaxUint16 + 1]uint16{}
)

type ActionFlag uint16

type NpbAction uint64 // aclgid | payload-slice | tunnel-type | Dep/Ip  | TapSide |  tunnel-id

type NpbActions struct {
	NpbAction

	aclGids []uint16
}

const (
	NPB_TUNNEL_TYPE_VXLAN = iota
	NPB_TUNNEL_TYPE_GRE_ERSPAN
	NPB_TUNNEL_TYPE_PCAP
)

const (
	TAPSIDE_SRC  = 0x1
	TAPSIDE_DST  = 0x2
	TAPSIDE_MASK = TAPSIDE_SRC | TAPSIDE_DST
	TAPSIDE_ALL  = TAPSIDE_SRC | TAPSIDE_DST
)

const (
	RESOURCE_GROUP_TYPE_DEV  = 0x1
	RESOURCE_GROUP_TYPE_IP   = 0x2
	RESOURCE_GROUP_TYPE_MASK = RESOURCE_GROUP_TYPE_DEV | RESOURCE_GROUP_TYPE_IP
)

func UpdateTunnelMaps(aclGids, ipIds []uint16, ips []net.IP) {
	// 数据再次更新后会有残余, 但不影响使用
	for i, id := range aclGids {
		tunnelIpMap[id] = ips[i]
		tunnelIpIdMap[id] = ipIds[i]
	}
}

func GetTunnelIp(aclGid uint16) net.IP {
	return tunnelIpMap[aclGid]
}

func GetTunnelIpId(aclGid uint16) uint16 {
	return tunnelIpIdMap[aclGid]
}

func (n *NpbActions) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(uint64(n.NpbAction))
	encoder.WriteU16Slice(n.aclGids)
}

func (n *NpbActions) Decode(decoder *codec.SimpleDecoder) {
	n.NpbAction = NpbAction(decoder.ReadU64())
	n.aclGids = decoder.ReadU16Slice()
}

func (a NpbAction) TapSideCompare(flag int) bool {
	return (a.TapSide() & flag) == flag
}

func (a NpbAction) TapSide() int {
	return int((a >> 26) & TAPSIDE_MASK)
}

func (a *NpbAction) SetTapSide(flag int) {
	*a &= ^NpbAction(TAPSIDE_MASK << 26)
	*a |= NpbAction((flag & TAPSIDE_MASK) << 26)
}

func (a *NpbAction) AddTapSide(flag int) {
	*a |= NpbAction((flag & TAPSIDE_MASK) << 26)
}

func (a *NpbAction) ReverseTapSide() NpbAction {
	if a.TapSide() == TAPSIDE_ALL {
		return *a
	}

	return *a ^ NpbAction(uint64(TAPSIDE_MASK)<<26)
}

func (a NpbAction) ResourceGroupTypeCompare(flag int) bool {
	return (a.ResourceGroupType() & flag) == flag
}

func (a *NpbAction) AddResourceGroupType(groupType int) {
	*a |= ((NpbAction(groupType & RESOURCE_GROUP_TYPE_MASK)) << 28)
}

func (a NpbAction) ResourceGroupType() int {
	return int((a >> 28) & RESOURCE_GROUP_TYPE_MASK)
}

func (a NpbAction) TunnelGid() uint16 {
	return uint16(a >> 48)
}

func (a NpbAction) TunnelIpId() uint16 {
	if a.TunnelType() == NPB_TUNNEL_TYPE_PCAP {
		return 0
	}
	return GetTunnelIpId(uint16(a >> 48))
}

func (a NpbAction) TunnelIp() net.IP {
	if a.TunnelType() == NPB_TUNNEL_TYPE_PCAP {
		return nil
	}
	return GetTunnelIp(uint16(a >> 48))
}

func (a NpbAction) TunnelId() uint32 {
	return uint32(a & 0xffffff)
}

func (a *NpbAction) SetTunnelId(id uint32) {
	*a &= ^NpbAction(0xffffff)
	*a |= NpbAction(id & 0xffffff)
}

func (a NpbAction) PayloadSlice() uint16 {
	return uint16((a >> 32) & 0xffff)
}

func (a *NpbAction) SetPayloadSlice(payload uint16) {
	*a &= ^NpbAction(0xffff << 32)
	*a |= NpbAction(uint64(payload) << 32)
}

func (a NpbAction) TunnelType() uint8 {
	return uint8((a >> 30) & 0x3)
}

func (a NpbAction) String() string {
	if a.TunnelType() == NPB_TUNNEL_TYPE_PCAP {
		return fmt.Sprintf("{gid: %d type: %d slice %d side: %d group: %d}", a.TunnelGid(), a.TunnelType(), a.PayloadSlice(), a.TapSide(), a.ResourceGroupType())
	} else {
		return fmt.Sprintf("{%d@%s gid: %d type: %d slice %d side: %d group: %d}", a.TunnelId(), a.TunnelIp(), a.TunnelGid(), a.TunnelType(), a.PayloadSlice(), a.TapSide(), a.ResourceGroupType())
	}
}

func ToNpbAction(aclGid, id uint32, tunnelType, group, tapSide uint8, slice uint16) NpbAction {
	return NpbAction(uint64(aclGid&0xffff)<<48 | uint64(slice)<<32 |
		uint64(tunnelType&0x3)<<30 | (uint64(group)&RESOURCE_GROUP_TYPE_MASK)<<28 | (uint64(tapSide)&TAPSIDE_MASK)<<26 | uint64(id&0xffffff))
}

func (a *NpbActions) AddAclGid(aclGids ...uint16) {
	for _, m := range aclGids {
		repeat := false
		for _, n := range a.aclGids {
			if m == n {
				repeat = true
				break
			}
		}
		if !repeat {
			a.aclGids = append(a.aclGids, m)
		}
	}
}

func (a NpbActions) GetAclGid() []uint16 {
	return a.aclGids
}

func (a NpbActions) doCompress() bool {
	return a.TunnelType() == NPB_TUNNEL_TYPE_PCAP && a.PayloadSlice() == 0
}

func (a *NpbActions) ReverseTapSide() NpbActions {
	action := NpbActions{}
	action.NpbAction = a.NpbAction.ReverseTapSide()
	action.aclGids = make([]uint16, len(a.aclGids))
	copy(action.aclGids, a.aclGids)
	return action
}

func (a NpbActions) String() string {
	return fmt.Sprintf("{%s gids: %v}", a.NpbAction, a.aclGids)
}

func ToNpbActions(aclGid, id uint32, tunnelType, group, tapSide uint8, slice uint16) NpbActions {
	return NpbActions{ToNpbAction(aclGid, id, tunnelType, group, tapSide, slice), []uint16{uint16(aclGid)}}
}

const (
	ACTION_PACKET_CAPTURING ActionFlag = 1 << iota
	_
	_
	_
	ACTION_COMPRESS_HEADER
)

func (f ActionFlag) String() string {
	s := "|"
	if f&ACTION_PACKET_CAPTURING != 0 {
		s += "PCAP|"
	}
	if f&ACTION_COMPRESS_HEADER != 0 {
		s += "COMPRESS|"
	}
	return s
}

type PolicyData struct {
	AclActions  []AclAction
	NpbActions  []NpbActions
	AclId       uint32
	ActionFlags ActionFlag
}

func (p *PolicyData) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(uint32(len(p.AclActions)))
	for i := range p.AclActions {
		p.AclActions[i].Encode(encoder)
	}

	encoder.WriteU32(uint32(len(p.NpbActions)))
	for i := range p.NpbActions {
		p.NpbActions[i].Encode(encoder)
	}

	encoder.WriteU32(p.AclId)
	encoder.WriteU16(uint16(p.ActionFlags))
}

func (p *PolicyData) Decode(decoder *codec.SimpleDecoder) {
	l := decoder.ReadU32()
	if l > 0 {
		p.AclActions = make([]AclAction, l)
		for i := range p.AclActions {
			p.AclActions[i].Decode(decoder)
		}
	}
	l = decoder.ReadU32()
	if l > 0 {
		p.NpbActions = make([]NpbActions, l)
		for i := range p.NpbActions {
			p.NpbActions[i].Decode(decoder)
		}
	}

	p.AclId = decoder.ReadU32()
	p.ActionFlags = ActionFlag(decoder.ReadU16())
}

type DirectionType uint8

const (
	NO_DIRECTION DirectionType = 0
)

const (
	FORWARD DirectionType = 1 << iota
	BACKWARD
)

// keys (16b ACLGID + 16b ActionFlags + ), values (2b Directions)
type AclAction uint64

func (a *AclAction) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(uint64(*a))
}

func (a *AclAction) Decode(decoder *codec.SimpleDecoder) {
	*a = AclAction(decoder.ReadU64())
}

func (a AclAction) SetACLGID(aclGID uint16) AclAction {
	a &= ^AclAction(0xFFFF << 48)
	a |= AclAction(aclGID&0xFFFF) << 48
	return a
}

func (a AclAction) SetActionFlags(actionFlags ActionFlag) AclAction {
	a &= ^AclAction(0xFFFF << 32)
	a |= AclAction(actionFlags&0xFFFF) << 32
	return a
}

func (a AclAction) AddActionFlags(actionFlags ActionFlag) AclAction {
	a |= AclAction(actionFlags&0xFFFF) << 32
	return a
}

func (a AclAction) SetDirections(directions DirectionType) AclAction {
	a &= ^AclAction(0x3 << 12)
	a |= AclAction(directions&0x3) << 12
	return a
}

func (a AclAction) AddDirections(directions DirectionType) AclAction {
	a |= AclAction(directions&0x3) << 12
	return a
}

func (a AclAction) ReverseDirection() AclAction {
	switch a.GetDirections() {
	case FORWARD:
		return a.SetDirections(BACKWARD)
	case BACKWARD:
		return a.SetDirections(FORWARD)
	}
	return a
}

func (a AclAction) GetACLGID() uint16 {
	return uint16(((a >> 48) & 0xFFFF))
}

func (a AclAction) GetActionFlags() ActionFlag {
	return ActionFlag((a >> 32) & 0xFFFF)
}

func (a AclAction) GetDirections() DirectionType {
	return DirectionType((a >> 12) & 0x3)
}

func (a AclAction) String() string {
	return fmt.Sprintf("{GID: %d ActionFlags: %s Directions: %d}",
		a.GetACLGID(), a.GetActionFlags().String(), a.GetDirections())
}

func (d *PolicyData) GobEncode() ([]byte, error) {
	return []byte{}, nil
}

func (d *PolicyData) GobDecode(in []byte) error {
	return nil
}

func (d *PolicyData) Valid() bool {
	return d.AclId != 0
}

// 如果双方向都匹配了同一策略，对应的NpbActions Merge后会是TAPSIDE_ALL，
// 此时只保留TAPSIDE_SRC方向，即对应只处理src为true的tx流量
func (d *PolicyData) FormatNpbAction() {
	for index, _ := range d.NpbActions {
		if d.NpbActions[index].TapSide() == TAPSIDE_ALL &&
			d.NpbActions[index].TunnelType() != NPB_TUNNEL_TYPE_PCAP {
			d.NpbActions[index].SetTapSide(TAPSIDE_SRC)
		}
	}
}

func (d *PolicyData) dedupNpbAction(packet *LookupKey) []NpbActions {
	if len(d.NpbActions) == 0 || packet.Tap != TAP_TOR {
		return d.NpbActions
	}

	validActions := make([]NpbActions, 0, len(d.NpbActions))
	for _, action := range d.NpbActions {
		if (action.TapSideCompare(TAPSIDE_SRC) == true && packet.L2End0 == true) ||
			(action.TapSideCompare(TAPSIDE_DST) == true && packet.L2End1 == true) {
			if action.ResourceGroupTypeCompare(RESOURCE_GROUP_TYPE_DEV) {
				validActions = append(validActions, action)
			} else if (action.TapSideCompare(TAPSIDE_SRC) == true && packet.L3End0 == true) ||
				(action.TapSideCompare(TAPSIDE_DST) == true && packet.L3End1 == true) {
				validActions = append(validActions, action)
			}
		}
	}
	return validActions
}

func (d *PolicyData) Dedup(packet *LookupKey) {
	if len(d.NpbActions) == 0 || packet.Tap != TAP_TOR {
		return
	}
	validActions := d.dedupNpbAction(packet)
	if len(validActions) == 0 && d.ActionFlags == 0 {
		*d = *INVALID_POLICY_DATA
		return
	}
	d.NpbActions = validActions
}

func (d *PolicyData) MergeNpbAction(actions []NpbActions, aclID uint32, directions ...DirectionType) {
	if d.AclId == 0 {
		d.AclId = aclID
	}
	for _, n := range actions {
		repeat := false
		for index, m := range d.NpbActions {
			if m.NpbAction == n.NpbAction {
				d.NpbActions[index].AddAclGid(n.GetAclGid()...)
				repeat = true
				break
			}

			if m.TunnelIpId() != n.TunnelIpId() || m.TunnelId() != n.TunnelId() || m.TunnelType() != n.TunnelType() {
				continue
			}
			if n.PayloadSlice() == 0 ||
				n.PayloadSlice() > m.PayloadSlice() {
				d.NpbActions[index].SetPayloadSlice(n.PayloadSlice())
			}
			d.NpbActions[index].AddResourceGroupType(n.ResourceGroupType())
			if len(directions) > 0 {
				d.NpbActions[index].SetTapSide(int(directions[0]))
			} else {
				d.NpbActions[index].AddTapSide(n.TapSide())
			}
			d.NpbActions[index].AddAclGid(n.GetAclGid()...)
			repeat = true
		}
		if !repeat {
			npbAction := n
			if len(directions) > 0 {
				npbAction.SetTapSide(int(directions[0]))
			}
			// 只有PCAP会有ACTION_COMPRESS_HEADER, 并且不会被去重
			if npbAction.doCompress() {
				d.ActionFlags |= ACTION_COMPRESS_HEADER
			}
			d.NpbActions = append(d.NpbActions, npbAction)
		}
	}
}

func (d *PolicyData) MergeAclAction(actions []AclAction, aclID uint32, directions ...DirectionType) {
	if d.AclId == 0 {
		d.AclId = aclID
	}
	for _, newAclAction := range actions {
		if len(directions) > 0 {
			newAclAction = newAclAction.SetDirections(directions[0])
		}

		exist := false
		for j, existAclAction := range d.AclActions { // 按ACLGID和TagTemplates合并
			if newAclAction.GetACLGID() == existAclAction.GetACLGID() {
				exist = true
				d.AclActions[j] = existAclAction.AddDirections(newAclAction.GetDirections()).
					AddActionFlags(newAclAction.GetActionFlags())
				d.ActionFlags |= newAclAction.GetActionFlags()
				break
			}
		}
		if exist {
			continue
		}
		// 无需再按照ACLGID和ActionFlags合并，因为他们的TagTemplates肯定相同

		d.AclActions = append(d.AclActions, newAclAction)
		d.ActionFlags |= newAclAction.GetActionFlags()
	}
}

func (d *PolicyData) Merge(aclActions []AclAction, npbActions []NpbActions, aclID uint32, directions ...DirectionType) {
	d.MergeAclAction(aclActions, aclID, directions...)
	d.MergeNpbAction(npbActions, aclID, directions...)
}

func (d *PolicyData) MergeNpbAndSwapDirection(actions []NpbActions, aclID uint32) {
	newNpbActions := make([]NpbActions, len(actions))
	for i, _ := range actions {
		newNpbActions[i] = actions[i].ReverseTapSide()
	}

	d.MergeNpbAction(newNpbActions, aclID)
}

func (d *PolicyData) MergeAclAndSwapDirection(actions []AclAction, aclID uint32) {
	newAclActions := make([]AclAction, len(actions))
	for i, _ := range actions {
		newAclActions[i] = actions[i].ReverseDirection()
	}

	d.MergeAclAction(newAclActions, aclID)
}

func (d *PolicyData) MergeAndSwapDirection(aclActions []AclAction, npbActions []NpbActions, aclID uint32) {
	d.MergeAclAndSwapDirection(aclActions, aclID)
	d.MergeNpbAndSwapDirection(npbActions, aclID)
}

// ReverseData will return a reversed replica of the current PolicyData
func (d *PolicyData) ReverseData() *PolicyData {
	newPolicyData := ClonePolicyData(d)
	for i, aclAction := range newPolicyData.AclActions {
		newPolicyData.AclActions[i] = aclAction.ReverseDirection()
	}
	return newPolicyData
}

func (d *PolicyData) String() string {
	return fmt.Sprintf("{AclId: %d ActionFlags: %v AclActions: %v NpbActions: %v}",
		d.AclId, d.ActionFlags, d.AclActions, d.NpbActions)
}

var policyDataPool = pool.NewLockFreePool(func() interface{} {
	return new(PolicyData)
})

func AcquirePolicyData() *PolicyData {
	return policyDataPool.Get().(*PolicyData)
}

func ReleasePolicyData(d *PolicyData) {
	if d.AclActions != nil {
		d.AclActions = d.AclActions[:0]
	}
	*d = PolicyData{AclActions: d.AclActions}
	policyDataPool.Put(d)
}

func ClonePolicyData(d *PolicyData) *PolicyData {
	dup := AcquirePolicyData()
	*dup = *d
	dup.AclActions = make([]AclAction, len(d.AclActions))
	copy(dup.AclActions, d.AclActions)
	return dup
}
