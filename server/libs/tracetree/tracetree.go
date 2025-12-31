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

package tracetree

import (
	"fmt"
	"net"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const TRACE_TREE_VERSION_0X12 = 0x12 // before 20240827
const TRACE_TREE_VERSION_0X13 = 0x13
const TRACE_TREE_VERSION_0x14 = 0x14 // before 20251027
const TRACE_TREE_VERSION_0x15 = 0x15 // before 20251206
const TRACE_TREE_VERSION_0x16 = 0x16 // before 20251231
const TRACE_TREE_VERSION = 0x17

func HashSearchIndex(key string) uint64 {
	return utils.DJBHash(17, key)
}

type TraceTree struct {
	Time        uint32
	SearchIndex uint64
	OrgId       uint16
	TraceScore  uint8

	TraceId, TraceId2 string
	UID               uint64 // uid for deduplicated metrics by same trace_tree
	TreeNodes         []TreeNode

	encodedTreeNodes []byte
}

type SpanInfo struct {
	AutoServiceType0 uint8
	AutoServiceType1 uint8
	AutoServiceID0   uint32
	AutoServiceID1   uint32
	AppService0      string
	AppService1      string
	Endpoints        []string

	IsIPv4 bool
	IP40   uint32
	IP60   net.IP
	IP41   uint32
	IP61   net.IP
}

type NodeInfo struct {
	AutoServiceType uint8
	AutoServiceID   uint32
	AppService      string
	Endpoints0      []string
	Endpoints1      []string

	IsIPv4 bool
	IP4    uint32
	IP6    net.IP
}

type TreeNode struct {
	UniqParentSpanInfos []SpanInfo
	ParentNodeIndex     int32

	NodeInfo NodeInfo

	ChildIndices []int32 // helps with calculations, no need to write to Clickhouse
	PseudoLink   uint8
	Level        uint8  // helps with calculations, no need to write to Clickhouse
	UID          string // helps with calculations, no need to write to Clickhouse

	Topic         string
	QuerierRegion string

	ResponseDurationSum            uint64
	ResponseTotal                  uint32
	ResponseStatusServerErrorCount uint32
	Total                          uint32
}

func (t *TraceTree) Release() {
	ReleaseTraceTree(t)
}

func (t *TraceTree) OrgID() uint16 {
	return t.OrgId
}

func (t *TraceTree) NativeTagVersion() uint32 {
	return 0
}

func TraceTreeColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("search_index", ckdb.UInt64),
		ckdb.NewColumn("trace_id", ckdb.String).SetIndex(ckdb.IndexBloomfilter),
		ckdb.NewColumn("_trace_id_2", ckdb.String).SetIndex(ckdb.IndexBloomfilter),
		ckdb.NewColumn("encoded_span_list", ckdb.String),
	}
}

var poolTraceTree = pool.NewLockFreePool(func() *TraceTree {
	return new(TraceTree)
})

func AcquireTraceTree() *TraceTree {
	return poolTraceTree.Get()
}

func ReleaseTraceTree(t *TraceTree) {
	if t == nil {
		return
	}
	treeNodes := t.TreeNodes[:0]
	*t = TraceTree{}
	t.TreeNodes = treeNodes
	poolTraceTree.Put(t)
}

func (t *TraceTree) Encode() {
	encoder := &codec.SimpleEncoder{}
	t.encodedTreeNodes = t.encodedTreeNodes[:0]
	encoder.Init(t.encodedTreeNodes)
	encoder.WriteU8(TRACE_TREE_VERSION)
	encoder.WriteU64(t.UID)
	encoder.WriteU8(t.TraceScore)
	encoder.WriteU16(uint16(len(t.TreeNodes)))
	for _, node := range t.TreeNodes {
		// encode uniq parent span infos
		encoder.WriteU16(uint16(len(node.UniqParentSpanInfos)))
		for _, s := range node.UniqParentSpanInfos {
			encoder.WriteU8(s.AutoServiceType0)
			encoder.WriteU8(s.AutoServiceType1)
			encoder.WriteVarintU32(s.AutoServiceID0)
			encoder.WriteVarintU32(s.AutoServiceID1)
			encoder.WriteString255(s.AppService0)
			encoder.WriteString255(s.AppService1)
			encoder.WriteU16(uint16(len(s.Endpoints)))
			for _, e := range s.Endpoints {
				encoder.WriteString255(e)
			}

			encoder.WriteBool(s.IsIPv4)
			if s.IsIPv4 {
				encoder.WriteU32(s.IP40)
				encoder.WriteU32(s.IP41)
			} else {
				if len(s.IP60) == 0 {
					s.IP60 = net.IPv6zero
				}
				if len(s.IP61) == 0 {
					s.IP61 = net.IPv6zero
				}
				encoder.WriteIPv6(s.IP60)
				encoder.WriteIPv6(s.IP61)
			}
		}
		encoder.WriteZigzagU32(uint32(node.ParentNodeIndex))

		// node info
		nodeInfo := &node.NodeInfo
		encoder.WriteU8(nodeInfo.AutoServiceType)
		encoder.WriteVarintU32(nodeInfo.AutoServiceID)
		encoder.WriteString255(nodeInfo.AppService)
		encoder.WriteU16(uint16(len(nodeInfo.Endpoints0)))
		for _, e := range nodeInfo.Endpoints0 {
			encoder.WriteString255(e)
		}
		encoder.WriteU16(uint16(len(nodeInfo.Endpoints1)))
		for _, e := range nodeInfo.Endpoints1 {
			encoder.WriteString255(e)
		}

		encoder.WriteBool(nodeInfo.IsIPv4)
		if nodeInfo.IsIPv4 {
			encoder.WriteU32(nodeInfo.IP4)
		} else {
			if len(nodeInfo.IP6) == 0 {
				nodeInfo.IP6 = net.IPv6zero
			}
			encoder.WriteIPv6(nodeInfo.IP6)
		}

		encoder.WriteU8(node.PseudoLink)
		encoder.WriteString255(node.Topic)
		encoder.WriteString255(node.QuerierRegion)
		encoder.WriteVarintU64(node.ResponseDurationSum)
		encoder.WriteVarintU32(node.ResponseTotal)
		encoder.WriteVarintU32(node.ResponseStatusServerErrorCount)
		encoder.WriteVarintU32(node.Total)
	}
	t.encodedTreeNodes = encoder.Bytes()
}

func (t *TraceTree) Decode(decoder *codec.SimpleDecoder) error {
	version := decoder.ReadU8()
	if version != TRACE_TREE_VERSION && version != TRACE_TREE_VERSION_0X12 && version != TRACE_TREE_VERSION_0X13 {
		return fmt.Errorf("trace tree data version is %d expect version is %d", version, TRACE_TREE_VERSION)
	}
	t.UID = decoder.ReadU64()
	t.TraceScore = decoder.ReadU8()
	treeNodeCount := int(decoder.ReadU16())
	if cap(t.TreeNodes) < treeNodeCount {
		t.TreeNodes = make([]TreeNode, treeNodeCount)
	} else {
		t.TreeNodes = t.TreeNodes[:treeNodeCount]
	}
	for i := 0; i < treeNodeCount; i++ {
		n := &t.TreeNodes[i]
		// decode uniq parent span infos
		parentSpanCount := int(decoder.ReadU16())
		n.UniqParentSpanInfos = make([]SpanInfo, parentSpanCount)
		for j := 0; j < parentSpanCount; j++ {
			s := &n.UniqParentSpanInfos[j]
			s.AutoServiceType0 = decoder.ReadU8()
			s.AutoServiceType1 = decoder.ReadU8()
			s.AutoServiceID0 = decoder.ReadVarintU32()
			s.AutoServiceID1 = decoder.ReadVarintU32()
			s.AppService0 = decoder.ReadString255()
			s.AppService1 = decoder.ReadString255()
			endpointCount := int(decoder.ReadU16())
			s.Endpoints = make([]string, endpointCount)
			for k := 0; k < endpointCount; k++ {
				s.Endpoints[k] = decoder.ReadString255()
			}

			s.IsIPv4 = decoder.ReadBool()
			if s.IsIPv4 {
				s.IP40 = decoder.ReadU32()
				s.IP41 = decoder.ReadU32()
			} else {
				s.IP60 = make([]byte, 16)
				s.IP61 = make([]byte, 16)
				decoder.ReadIPv6(s.IP60)
				decoder.ReadIPv6(s.IP61)
			}
		}
		n.ParentNodeIndex = int32(decoder.ReadZigzagU32())

		nodeInfo := &n.NodeInfo
		nodeInfo.AutoServiceType = decoder.ReadU8()
		nodeInfo.AutoServiceID = decoder.ReadVarintU32()
		nodeInfo.AppService = decoder.ReadString255()
		endpointCount := int(decoder.ReadU16())
		nodeInfo.Endpoints0 = make([]string, endpointCount)
		for j := 0; j < endpointCount; j++ {
			nodeInfo.Endpoints0[j] = decoder.ReadString255()
		}
		endpointCount = int(decoder.ReadU16())
		nodeInfo.Endpoints1 = make([]string, endpointCount)
		for j := 0; j < endpointCount; j++ {
			nodeInfo.Endpoints1[j] = decoder.ReadString255()
		}
		nodeInfo.IsIPv4 = decoder.ReadBool()
		if nodeInfo.IsIPv4 {
			nodeInfo.IP4 = decoder.ReadU32()
		} else {
			nodeInfo.IP6 = make([]byte, 16)
			decoder.ReadIPv6(nodeInfo.IP6)
		}
		n.ChildIndices = n.ChildIndices[:0]
		n.Level = 0
		if version == TRACE_TREE_VERSION_0X12 {
			n.PseudoLink = 0
		} else {
			n.PseudoLink = decoder.ReadU8()
		}
		n.UID = ""
		n.Topic = decoder.ReadString255()
		if version >= TRACE_TREE_VERSION {
			n.QuerierRegion = decoder.ReadString255()
		}
		n.ResponseDurationSum = decoder.ReadVarintU64()
		n.ResponseTotal = decoder.ReadVarintU32()
		n.ResponseStatusServerErrorCount = decoder.ReadVarintU32()
		n.Total = decoder.ReadVarintU32()
	}
	if decoder.Failed() {
		return fmt.Errorf("trace tree decode failed, offset is %d, buf length is %d ", decoder.Offset(), len(decoder.Bytes()))
	}
	return nil
}
