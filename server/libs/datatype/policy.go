/*
 * Copyright (c) 2022 Yunshan Networks
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

package datatype

import (
	"fmt"
	"math"
	"net"

	"github.com/deepflowio/deepflow/server/libs/codec"
)

var (
	INVALID_POLICY_DATA = new(PolicyData)

	// 通过aclGid分别查询tunnelIp或tunnelIpId
	tunnelIpMap   = [math.MaxUint16 + 1]net.IP{}
	tunnelIpIdMap = [math.MaxUint16 + 1]uint16{}
)

type ActionFlag uint16

type NpbAction uint64 // aclgid | payload-slice | tunnel-type | TapSide |  tunnel-id

type NpbActions struct {
	NpbAction

	aclGids []uint16
}

const (
	NPB_TUNNEL_TYPE_VXLAN = iota
	NPB_TUNNEL_TYPE_GRE_ERSPAN
	NPB_TUNNEL_TYPE_PCAP
	NPB_TUNNEL_TYPE_NPB_DROP
)

const (
	TAPSIDE_SRC  = 0x1
	TAPSIDE_DST  = 0x2
	TAPSIDE_MASK = TAPSIDE_SRC | TAPSIDE_DST
	TAPSIDE_ALL  = TAPSIDE_SRC | TAPSIDE_DST
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

func (a NpbAction) GetDirections() DirectionType {
	return DirectionType(a.TapSide())
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
		return fmt.Sprintf("{gid: %d type: %d slice %d side: %d}", a.TunnelGid(), a.TunnelType(), a.PayloadSlice(), a.TapSide())
	} else {
		return fmt.Sprintf("{%d@%s gid: %d type: %d slice %d side: %d}", a.TunnelId(), a.TunnelIp(), a.TunnelGid(), a.TunnelType(), a.PayloadSlice(), a.TapSide())
	}
}

func ToNpbAction(aclGid, id uint32, tunnelType, tapSide uint8, slice uint16) NpbAction {
	return NpbAction(uint64(aclGid&0xffff)<<48 | uint64(slice)<<32 |
		uint64(tunnelType&0x3)<<30 | (uint64(tapSide)&TAPSIDE_MASK)<<26 | uint64(id&0xffffff))
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

func (a NpbActions) isTunnelType(tunnelType uint8) bool {
	return a.TunnelType() == tunnelType
}

func (a NpbActions) doTridentPcap() bool {
	return a.isTunnelType(NPB_TUNNEL_TYPE_PCAP)
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

func ToNpbActions(aclGid, id uint32, tunnelType, tapSide uint8, slice uint16) NpbActions {
	return NpbActions{ToNpbAction(aclGid, id, tunnelType, tapSide, slice), []uint16{uint16(aclGid)}}
}

const (
	ACTION_PCAP ActionFlag = 1 << iota
	ACTION_NPB
	ACTION_NPB_DROP
)

func (f ActionFlag) String() string {
	s := "|"
	if f&ACTION_PCAP != 0 {
		s += "PCAP|"
	}
	if f&ACTION_NPB != 0 {
		s += "NPB|"
	}
	if f&ACTION_NPB_DROP != 0 {
		s += "NPB_DROP|"
	}
	return s
}

type PolicyData struct {
	NpbActions  []NpbActions
	AclId       uint32
	ActionFlags ActionFlag
}

func (p *PolicyData) Encode(encoder *codec.SimpleEncoder) {
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
	if len(d.NpbActions) == 0 || packet.TapType != TAP_CLOUD {
		return d.NpbActions
	}

	validActions := make([]NpbActions, 0, len(d.NpbActions))
	for _, action := range d.NpbActions {
		if action.TunnelType() == NPB_TUNNEL_TYPE_PCAP ||
			(action.TapSideCompare(TAPSIDE_SRC) && packet.L2End0 && packet.L3End0) ||
			(action.TapSideCompare(TAPSIDE_DST) && packet.L2End1 && packet.L3End1) {
			validActions = append(validActions, action)
		}
	}
	return validActions
}

func (d *PolicyData) Dedup(packet *LookupKey) {
	if len(d.NpbActions) == 0 || packet.TapType != TAP_CLOUD {
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
			// PCAP相同aclgid的合并为一个，不同aclgid的不能合并
			if n.TunnelType() == NPB_TUNNEL_TYPE_PCAP || n.TunnelType() == NPB_TUNNEL_TYPE_NPB_DROP {
				// 应该有且仅有一个
				aclGid := n.GetAclGid()[0]
				repeatPcapAclGid := false
				for _, id := range m.GetAclGid() {
					if id == aclGid {
						repeatPcapAclGid = true
						break
					}
				}
				if !repeatPcapAclGid {
					continue
				}
			}

			if n.PayloadSlice() == 0 ||
				n.PayloadSlice() > m.PayloadSlice() {
				d.NpbActions[index].SetPayloadSlice(n.PayloadSlice())
			}
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
			if npbAction.isTunnelType(NPB_TUNNEL_TYPE_PCAP) {
				d.ActionFlags |= ACTION_PCAP
			} else if npbAction.isTunnelType(NPB_TUNNEL_TYPE_VXLAN) || npbAction.isTunnelType(NPB_TUNNEL_TYPE_GRE_ERSPAN) {
				d.ActionFlags |= ACTION_NPB
			} else if npbAction.isTunnelType(NPB_TUNNEL_TYPE_NPB_DROP) {
				d.ActionFlags |= ACTION_NPB_DROP
			}
			d.NpbActions = append(d.NpbActions, npbAction)
		}
	}
}

func (d *PolicyData) Merge(npbActions []NpbActions, aclID uint32, directions ...DirectionType) {
	d.MergeNpbAction(npbActions, aclID, directions...)
}

func (d *PolicyData) MergeNpbAndSwapDirection(actions []NpbActions, aclID uint32) {
	newNpbActions := make([]NpbActions, len(actions))
	for i, _ := range actions {
		newNpbActions[i] = actions[i].ReverseTapSide()
	}

	d.MergeNpbAction(newNpbActions, aclID)
}

func (d *PolicyData) MergeAndSwapDirection(npbActions []NpbActions, aclID uint32) {
	d.MergeNpbAndSwapDirection(npbActions, aclID)
}

func (d *PolicyData) ContainNpb() bool {
	return d.ActionFlags&ACTION_NPB_DROP == 0 && d.ActionFlags&ACTION_NPB != 0
}

func (d *PolicyData) ContainPcap() bool {
	return d.ActionFlags&ACTION_PCAP != 0
}

func (d *PolicyData) String() string {
	return fmt.Sprintf("{AclId: %d ActionFlags: %v NpbActions: %v}",
		d.AclId, d.ActionFlags, d.NpbActions)
}
