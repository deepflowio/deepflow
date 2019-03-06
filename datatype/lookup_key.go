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
	forwardMatched, backwardMatched []MatchedField
}

func (k *LookupKey) generateMatchedField(direction DirectionType) []MatchedField {
	matcheds := make([]MatchedField, 0, len(k.SrcGroupIds)*len(k.DstGroupIds))
	srcPort, dstPort := k.SrcPort, k.DstPort
	srcGroups, dstGroups := k.SrcGroupIds, k.DstGroupIds

	if direction == BACKWARD {
		srcPort, dstPort = k.DstPort, k.SrcPort
		srcGroups, dstGroups = k.DstGroupIds, k.SrcGroupIds
	}
	for _, srcGroup := range srcGroups {
		for _, dstGroup := range dstGroups {
			matched := MatchedField{}
			matched.Set(MATCHED_TAP_TYPE, uint16(k.Tap))
			matched.Set(MATCHED_PROTO, uint16(k.Proto))
			matched.Set(MATCHED_VLAN, uint16(k.Vlan))
			matched.Set(MATCHED_SRC_GROUP, srcGroup)
			matched.Set(MATCHED_DST_GROUP, dstGroup)
			matched.Set(MATCHED_SRC_PORT, srcPort)
			matched.Set(MATCHED_DST_PORT, dstPort)
			matcheds = append(matcheds, matched)
		}
	}
	return matcheds
}

func (k *LookupKey) GenerateMatchedField() {
	k.forwardMatched = k.generateMatchedField(FORWARD)
	k.backwardMatched = k.generateMatchedField(BACKWARD)
}

func (k *LookupKey) String() string {
	return fmt.Sprintf("%d %s:%v > %s:%v %v vlan: %v %v:%d > %v:%d proto: %v ttl %v tap: %v",
		k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType, k.Vlan,
		IpFromUint32(k.SrcIp), k.SrcPort, IpFromUint32(k.DstIp), k.DstPort, k.Proto, k.Ttl, k.Tap)
}

func (k *LookupKey) HasFeatureFlag(featureFlag FeatureFlags) bool {
	return k.FeatureFlag&featureFlag == featureFlag
}
