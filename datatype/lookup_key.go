package datatype

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type LookupKey struct {
	Timestamp                         time.Duration
	SrcMac, DstMac                    uint64
	SrcIp, DstIp                      uint32
	Src6Ip, Dst6Ip                    net.IP
	SrcPort, DstPort                  uint16
	EthType                           EthernetType
	Vlan                              uint16
	Proto                             uint8
	Ttl                               uint8
	L2End0, L2End1                    bool
	Tap                               TapType
	Invalid                           bool
	FastIndex                         int
	SrcGroupIds, DstGroupIds          []uint16 //资源组的再分组ID, 没有重复用于策略匹配
	SrcAllGroupIds, DstAllGroupIds    []uint16 //资源组的再分组ID，有重复用于aclgid bitmap生成
	FeatureFlag                       FeatureFlags
	ForwardMatched, BackwardMatched   MatchedField
	ForwardMatched6, BackwardMatched6 MatchedField6
}

func (k *LookupKey) generateMatchedField6(direction DirectionType, srcEpc, dstEpc uint16) {
	srcPort, dstPort := k.SrcPort, k.DstPort
	srcIp, dstIp := k.Src6Ip, k.Dst6Ip
	srcMac, dstMac := k.SrcMac, k.DstMac
	matched := &k.ForwardMatched6
	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcIp, dstIp = k.Dst6Ip, k.Src6Ip
		srcMac, dstMac = k.DstMac, k.SrcMac
		matched = &k.BackwardMatched6
	}
	matched.Set(MATCHED6_TAP_TYPE, uint64(k.Tap))
	matched.Set(MATCHED6_PROTO, uint64(k.Proto))
	matched.Set(MATCHED6_VLAN, uint64(k.Vlan))
	matched.Set(MATCHED6_SRC_MAC, srcMac)
	matched.Set(MATCHED6_DST_MAC, dstMac)
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
	srcMac, dstMac := k.SrcMac, k.DstMac
	matched := &k.ForwardMatched
	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcIp, dstIp = k.DstIp, k.SrcIp
		srcMac, dstMac = k.DstMac, k.SrcMac
		matched = &k.BackwardMatched
	}
	matched.Set(MATCHED_TAP_TYPE, uint64(k.Tap))
	matched.Set(MATCHED_PROTO, uint64(k.Proto))
	matched.Set(MATCHED_VLAN, uint64(k.Vlan))
	matched.Set(MATCHED_SRC_MAC, srcMac)
	matched.Set(MATCHED_DST_MAC, dstMac)
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
		return fmt.Sprintf("%d %s:%v > %s:%v %v vlan: %v %v.%d > %v.%d proto: %v ttl %v tap: %v",
			k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType, k.Vlan,
			k.Src6Ip, k.SrcPort, k.Dst6Ip, k.DstPort, k.Proto, k.Ttl, k.Tap)
	} else {
		return fmt.Sprintf("%d %s:%v > %s:%v %v vlan: %v %v:%d > %v:%d proto: %v ttl %v tap: %v",
			k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType, k.Vlan,
			IpFromUint32(k.SrcIp), k.SrcPort, IpFromUint32(k.DstIp), k.DstPort, k.Proto, k.Ttl, k.Tap)
	}
}

func (k *LookupKey) HasFeatureFlag(featureFlag FeatureFlags) bool {
	return k.FeatureFlag&featureFlag == featureFlag
}
