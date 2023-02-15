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
	"encoding/binary"
	"fmt"
	"net"
	"time"

	. "github.com/google/gopacket/layers"

	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type LookupKey struct {
	Timestamp                         time.Duration
	SrcMac, DstMac                    uint64
	SrcIp, DstIp                      uint32
	Src6Ip, Dst6Ip                    net.IP
	SrcPort, DstPort                  uint16
	EthType                           EthernetType
	L2End0, L2End1                    bool
	L3End0, L3End1                    bool
	L3EpcId0, L3EpcId1                uint16 // 目前仅droplet使用
	Proto                             uint8
	TapType                           TapType
	FeatureFlag                       FeatureFlags
	ForwardMatched, BackwardMatched   MatchedField
	ForwardMatched6, BackwardMatched6 MatchedField6
	FastIndex                         int
	TunnelId                          uint32 // 目前仅是腾讯GRE的key，用来查询L3EpcID
}

func (k *LookupKey) generateMatchedField6(direction DirectionType, srcEpc, dstEpc uint16) {
	srcPort, dstPort := k.SrcPort, k.DstPort
	srcIp, dstIp := k.Src6Ip, k.Dst6Ip
	matched := &k.ForwardMatched6
	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcIp, dstIp = k.Dst6Ip, k.Src6Ip
		matched = &k.BackwardMatched6
	}
	matched.Set(MATCHED6_TAP_TYPE, uint64(k.TapType))
	matched.Set(MATCHED6_PROTO, uint64(k.Proto))
	matched.Set(MATCHED6_SRC_IP0, binary.BigEndian.Uint64(srcIp))
	matched.Set(MATCHED6_SRC_IP1, binary.BigEndian.Uint64(srcIp[8:]))
	matched.Set(MATCHED6_DST_IP0, binary.BigEndian.Uint64(dstIp))
	matched.Set(MATCHED6_DST_IP1, binary.BigEndian.Uint64(dstIp[8:]))
	matched.Set(MATCHED6_SRC_EPC, uint64(srcEpc))
	matched.Set(MATCHED6_DST_EPC, uint64(dstEpc))
	matched.Set(MATCHED6_SRC_PORT, uint64(srcPort))
	matched.Set(MATCHED6_DST_PORT, uint64(dstPort))
}

func (k *LookupKey) generateMatchedField(direction DirectionType, srcEpc, dstEpc uint16) {
	srcPort, dstPort := k.SrcPort, k.DstPort
	srcIp, dstIp := k.SrcIp, k.DstIp
	matched := &k.ForwardMatched
	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcIp, dstIp = k.DstIp, k.SrcIp
		matched = &k.BackwardMatched
	}
	matched.Set(MATCHED_TAP_TYPE, uint64(k.TapType))
	matched.Set(MATCHED_PROTO, uint64(k.Proto))
	matched.Set(MATCHED_SRC_IP, uint64(srcIp))
	matched.Set(MATCHED_DST_IP, uint64(dstIp))
	matched.Set(MATCHED_SRC_EPC, uint64(srcEpc))
	matched.Set(MATCHED_DST_EPC, uint64(dstEpc))
	matched.Set(MATCHED_SRC_PORT, uint64(srcPort))
	matched.Set(MATCHED_DST_PORT, uint64(dstPort))
}

func (k *LookupKey) GenerateMatchedField(srcEpc, dstEpc uint16) {
	if len(k.Src6Ip) > 0 {
		k.generateMatchedField6(FORWARD, srcEpc, dstEpc)
		k.generateMatchedField6(BACKWARD, dstEpc, srcEpc)
	} else {
		k.generateMatchedField(FORWARD, srcEpc, dstEpc)
		k.generateMatchedField(BACKWARD, dstEpc, srcEpc)
	}
}

func (k *LookupKey) String() string {
	if k.EthType == EthernetTypeIPv6 {
		return fmt.Sprintf("%d %s:%v > %s:%v ethType: %v %v.%d.%v > %v.%d.%v proto: %v tapType: %v tunnel id: %d",
			k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType,
			k.Src6Ip, k.SrcPort, k.L3End0, k.Dst6Ip, k.DstPort, k.L3End1, k.Proto, k.TapType, k.TunnelId)
	} else {
		return fmt.Sprintf("%d %s:%v > %s:%v ethType: %v %v:%d:%v > %v:%d:%v proto: %v tapType: %v tunnel id: %d",
			k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType,
			IpFromUint32(k.SrcIp), k.SrcPort, k.L3End0, IpFromUint32(k.DstIp), k.DstPort, k.L3End1, k.Proto, k.TapType, k.TunnelId)
	}
}

func (k *LookupKey) HasFeatureFlag(featureFlag FeatureFlags) bool {
	return k.FeatureFlag&featureFlag == featureFlag
}
