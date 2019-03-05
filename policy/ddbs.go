package policy

import (
	//	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type TableItem struct {
	matchBit uint64

	policy *PolicyData
}

type Ddbs struct {
	FastPath
	InterestTable

	maskVector uint64 // 根据所有策略计算出的M-Vector, 用于创建查询table
	//	table      [1 << 10][]TableItem // 策略使用计算出的索引从这里查询策略
}

/*

func (d *Ddbs) generateAclBits(acls []*Acl) {
	for _, acl := range acls {
		// 使用原目的资源组获取其对应的MAC IP

		// 根据策略字段生成对应的bits
		// acl.generateBits()
	}
}

func (d *Ddbs) generateMaskVector(acls []*Acl) {
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]uint32{}
	for i := uint16(0); i < 128; i++ {
		matched0, matched1 := uint16(0), uint16(0)
		for _, acl := range acls {
			for j := 0; j < len(acl.MatchBits); j++ {
				if acl.MatchBits[j].MatchBit(i, 0) {
					matched0++
				}
				if acl.MatchBits[j].MatchBit(i, 1) {
					matched1++
				}
			}
		}

		index := abs(matched0 - matched1)
		table[index] = append(table[index], i)
	}

	vectorBits := make([]uint16, 0, 10)
	// 使用对应差值最小的10个bit位做为MaskVector
	for i := 0; i < math.MaxUint16 && len(vectorBits) < 10; i++ {
		for _, bitOffset := range table[i] {
			vectorBits = append(vectorBits, bitOffset)
			if len(vectorBits) >= 10 {
				break
			}
		}
	}
	//d.maskVector.set(vectorBits...)
}

func (d *Ddbs) generateVectorTable(acls []*Acl) {
	for _, acl := range acls {
		for _, match := range acl.MatchBits {
			index := match.generateTableIndex(d.maskVector)
			table[index] = append(table[index], TableItem{match, acl.generatePolicyData()})
		}
	}
}

func (d *Ddbs) generateDdbsTable(acls []*Acl) {
	// 生成策略对应的bits
	d.generateAclBits(acls)
	d.generateMaskVector(acls)
	d.generateVectorTable(acls)
}

func (d *Ddbs) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) (*EndpointStore, *PolicyData) {
	policy := new(PolicyData)
	for _, direction := range []Direction{FORWARD, BACKWARD} {
		index := packet.generateTableIndex(d.maskVector, direction)
		for _, item := range d.table[index] {
			if item.matchBit.Equal(packet) {
				policy.Merge(item.PolicyData, direction)
			}
		}
	}
	return policy
}

func (d *Ddbs) UpdateAcls(acls []*Acl) {
	// 生成策略InterestMap,更新策略
	d.GenerateInterestMaps(acls)
	d.GenerateGroupAclGidMaps(acls)

	// 生成Ddbs查询表
	d.generateDdbsTable(acls)
}
*/
