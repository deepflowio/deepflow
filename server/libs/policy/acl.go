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

package policy

import (
	"fmt"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

const (
	_FIELD_NODE_SIZE  = (MATCHED_FIELD_LEN * 8 * 2) + 8  // 56
	_FIELD6_NODE_SIZE = (MATCHED_FIELD6_LEN * 8 * 2) + 8 // 104
)

type Link6 struct {
	Head  *Match6Node
	Count uint32
}

type Match6Node struct {
	Matched, MatchedMask MatchedField6

	Next *Match6Node
}

func (n *Match6Node) GetAllTableIndex(maskVector *MatchedField6, min, max int, vectorBits []int) []uint16 {
	return n.Matched.GetAllTableIndex(maskVector, &n.MatchedMask, min, max, vectorBits)
}

func (l *Link6) reset() {
	l.Head = nil
	l.Count = 0
}

func (l *Link6) add(node *Match6Node) {
	node.Next = l.Head
	l.Head = node
	l.Count += 1
}

type Link struct {
	Head  *MatchNode
	Count uint32
}

func (l *Link) reset() {
	l.Head = nil
	l.Count = 0
}

func (l *Link) add(node *MatchNode) {
	node.Next = l.Head
	l.Head = node
	l.Count += 1
}

type MatchNode struct {
	Matched, MatchedMask MatchedField

	Next *MatchNode
}

func (n *MatchNode) GetAllTableIndex(maskVector *MatchedField, min, max int, vectorBits []int) []uint16 {
	return n.Matched.GetAllTableIndex(maskVector, &n.MatchedMask, min, max, vectorBits)
}

type Acl struct {
	Id           uint32
	TapType      TapType
	SrcGroups    []uint32
	DstGroups    []uint32
	SrcPortRange []PortRange // 0仅表示采集端口0
	DstPortRange []PortRange // 0仅表示采集端口0
	Proto        uint16      // 256表示全采集, 0表示采集采集协议0
	NpbActions   []NpbActions
	FieldLink    Link
	Field6Link   Link6
	policy       PolicyData
}

const (
	PROTO_ALL = 256
)

func (a *Acl) InitPolicy() {
	a.policy.Merge(a.NpbActions, a.Id)
}

func (a *Acl) Reset() {
	a.FieldLink.reset()
	a.Field6Link.reset()
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
	for _, ports := range a.SrcPortRange {
		srcSegment = append(srcSegment, newPortSegments(ports)...)
	}
	for _, ports := range a.DstPortRange {
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
	nodes := make([]MatchNode, len(srcPorts)*len(dstPorts))
	for i, srcPort := range srcPorts {
		for j, dstPort := range dstPorts {
			index := i*len(dstPorts) + j
			match, mask := &nodes[index].Matched, &nodes[index].MatchedMask

			match.Set(MATCHED_TAP_TYPE, uint64(a.TapType))
			match.Set(MATCHED_SRC_IP, uint64(srcIps.getIp()))
			match.Set(MATCHED_SRC_EPC, uint64(srcIps.getEpcId()))
			match.Set(MATCHED_DST_IP, uint64(dstIps.getIp()))
			match.Set(MATCHED_DST_EPC, uint64(dstIps.getEpcId()))
			match.Set(MATCHED_SRC_PORT, uint64(srcPort.port))
			match.Set(MATCHED_DST_PORT, uint64(dstPort.port))

			mask.SetMask(MATCHED_TAP_TYPE, uint64(a.TapType))
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

			a.FieldLink.add(&nodes[index])
		}
	}
}

func (a *Acl) generateMatchedField6(srcMac, dstMac uint64, srcIps, dstIps ipSegment, srcPorts, dstPorts []portSegment) {
	nodes := make([]Match6Node, len(srcPorts)*len(dstPorts))
	for i, srcPort := range srcPorts {
		for j, dstPort := range dstPorts {
			index := i*len(dstPorts) + j
			match, mask := &nodes[index].Matched, &nodes[index].MatchedMask

			match.Set(MATCHED6_TAP_TYPE, uint64(a.TapType))
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

			mask.SetMask(MATCHED6_TAP_TYPE, uint64(a.TapType))
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

			a.Field6Link.add(&nodes[index])
		}
	}
}

func (a *Acl) generateMatched(srcIps, dstIps []ipSegment) {
	srcPorts, dstPorts := a.generatePortSegment()
	for _, srcIp := range srcIps {
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
	return fmt.Sprintf("Id:%v TapType:%v SrcGroups:%v DstGroups:%v SrcPortRange:[%v] DstPortRange:[%v] Proto:%v NpbActions:%s",
		a.Id, a.TapType, a.SrcGroups, a.DstGroups, a.SrcPortRange, a.DstPortRange, a.Proto, a.NpbActions)
}
