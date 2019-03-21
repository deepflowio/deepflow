package datatype

import (
	"fmt"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type LookupKey struct {
	Timestamp                       time.Duration
	SrcMac, DstMac                  uint64
	SrcIp, DstIp                    uint32
	SrcPort, DstPort                uint16
	EthType                         EthernetType
	Vlan                            uint16
	Proto                           uint8
	Ttl                             uint8
	L2End0, L2End1                  bool
	Tap                             TapType
	Invalid                         bool
	FastIndex                       int
	SrcGroupIds, DstGroupIds        []uint16 //资源组的再分组ID, 没有重复用于策略匹配
	SrcAllGroupIds, DstAllGroupIds  []uint16 //资源组的再分组ID，有重复用于aclgid bitmap生成
	FeatureFlag                     FeatureFlags
	ForwardMatched, BackwardMatched MatchedField
}

func (k *LookupKey) generateMatchedField(direction DirectionType, srcEpc, dstEpc uint16) {
	srcPort, dstPort := k.SrcPort, k.DstPort
	srcIp, dstIp := k.SrcIp, k.DstIp
	srcMac, dstMac := k.SrcMac, k.DstMac
	matched := &k.ForwardMatched
	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcIp, dstIp = k.DstIp, k.SrcIp
		srcMac, dstMac = k.DstMac, k.SrcMac
		matched = &k.BackwardMatched
	}
	matched.Set(MATCHED_TAP_TYPE, uint32(k.Tap))
	matched.Set(MATCHED_PROTO, uint32(k.Proto))
	matched.Set(MATCHED_VLAN, uint32(k.Vlan))
	matched.Set(MATCHED_SRC_MAC, uint32(srcMac&0xffffffff))
	matched.Set(MATCHED_DST_MAC, uint32(dstMac&0xffffffff))
	matched.Set(MATCHED_SRC_IP, srcIp)
	matched.Set(MATCHED_DST_IP, dstIp)
	matched.Set(MATCHED_SRC_EPC, uint32(srcEpc))
	matched.Set(MATCHED_DST_EPC, uint32(dstEpc))
	matched.Set(MATCHED_SRC_PORT, uint32(srcPort))
	matched.Set(MATCHED_DST_PORT, uint32(dstPort))
}

func (k *LookupKey) GenerateMatchedField(srcEpc, dstEpc uint16) {
	k.generateMatchedField(FORWARD, srcEpc, dstEpc)
	k.generateMatchedField(BACKWARD, dstEpc, srcEpc)
}

func (k *LookupKey) String() string {
	return fmt.Sprintf("%d %s:%v > %s:%v %v vlan: %v %v:%d > %v:%d proto: %v ttl %v tap: %v",
		k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType, k.Vlan,
		IpFromUint32(k.SrcIp), k.SrcPort, IpFromUint32(k.DstIp), k.DstPort, k.Proto, k.Ttl, k.Tap)
}

func (k *LookupKey) HasFeatureFlag(featureFlag FeatureFlags) bool {
	return k.FeatureFlag&featureFlag == featureFlag
}
