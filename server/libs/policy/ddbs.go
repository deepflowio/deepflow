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

package policy

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/shirou/gopsutil/process"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

type link6 struct {
	head  *Table6Item
	count uint32
}

type Table6Item struct {
	match, mask *MatchedField6

	policy *PolicyData

	next *Table6Item
}

type link struct {
	head  *TableItem
	count uint32
}

type TableItem struct {
	match, mask *MatchedField

	policy *PolicyData

	next *TableItem
}

const (
	_TABLE_ITEM_SIZE = 8 * 4
)

const (
	MASK_VECTOR_MAX_SIZE = 16
	MASK_VECTOR_MIN_SIZE = 4
	TABLE_SIZE           = 1 << MASK_VECTOR_MAX_SIZE
)

const (
	_LEVEL_MIN = 1
	_LEVEL_MAX = 16

	// 策略阈值和内存阈值是相关联的
	// 1. 实际内存阈值大于_MEMORY_LIMIT时，策略阈值始终为_POLICY_LIMIT
	// 2. 实际内存阈值小于_MEMORY_LIMIT时，策略阈值等比例减少
	_POLICY_LIMIT = 5000000
	_MEMORY_LIMIT = 1 << 20
)

type vector struct {
	maskMinBit, maskMaxBit int
	vectorBits             []int
	maskVector             MatchedField // 根据所有策略计算出的M-Vector, 用于创建查询table
	itemCount              uint64
}

func (v *vector) generateMaskVector(acls []*Acl, vectorSize int, table *[math.MaxUint16][]int) {
	vectorBits := make([]int, 0, vectorSize)
	// 使用对应差值最小的10个bit位做为MaskVector
	for i := 0; i < math.MaxUint16 && len(vectorBits) < vectorSize; i++ {
		for _, bitOffset := range table[i] {
			vectorBits = append(vectorBits, bitOffset)
			if len(vectorBits) >= vectorSize {
				break
			}
		}
	}
	sort.Ints(vectorBits)
	v.maskMinBit = vectorBits[0]
	v.maskMaxBit = vectorBits[vectorSize-1]
	v.maskVector.SetBits(vectorBits...)
	v.vectorBits = vectorBits
}

func (v *vector) calcVectorTableMemory(acls []*Acl) uint64 {
	num := uint64(0)
	for _, acl := range acls {
		for node := acl.FieldLink.Head; node != nil; node = node.Next {
			indexs := node.GetAllTableIndex(&v.maskVector, v.maskMinBit, v.maskMaxBit, v.vectorBits)
			num += uint64(len(indexs))
		}
	}
	v.itemCount = num
	return num * _TABLE_ITEM_SIZE
}

type vector6 struct {
	mask6MinBit, mask6MaxBit int
	vector6Bits              []int
	maskVector6              MatchedField6 // 根据所有策略计算出的M-Vector, 用于创建查询table
	itemCount                uint64
}

func (v *vector6) generateMaskVector(acls []*Acl, vectorSize int, table *[math.MaxUint16][]int) {
	vectorBits := make([]int, 0, vectorSize)
	// 使用对应差值最小的10个bit位做为MaskVector
	for i := 0; i < math.MaxUint16 && len(vectorBits) < vectorSize; i++ {
		for _, bitOffset := range table[i] {
			vectorBits = append(vectorBits, bitOffset)
			if len(vectorBits) >= vectorSize {
				break
			}
		}
	}
	sort.Ints(vectorBits)
	v.mask6MinBit = vectorBits[0]
	v.mask6MaxBit = vectorBits[vectorSize-1]
	v.maskVector6.SetBits(vectorBits...)
	v.vector6Bits = vectorBits
}

func (v *vector6) calcVectorTableMemory(acls []*Acl) uint64 {
	num := uint64(0)
	for _, acl := range acls {
		for node := acl.Field6Link.Head; node != nil; node = node.Next {
			indexs := node.GetAllTableIndex(&v.maskVector6, v.mask6MinBit, v.mask6MaxBit, v.vector6Bits)
			num += uint64(len(indexs))
		}
	}
	v.itemCount = num
	return num * _TABLE_ITEM_SIZE
}

type Ddbs struct {
	FastPath
	InterestTable
	groupIpMap map[uint16][]ipSegment

	FastPathDisable     bool
	queueCount          int
	level, currentLevel int

	RawAcls []*Acl

	FirstPathHit         uint64
	AclHitMax            uint32
	UnmatchedPacketCount uint64
	memoryLimit          uint64

	// ipv4
	vector
	table *[TABLE_SIZE]*link // 策略使用计算出的索引从这里查询策略
	// ipv6
	vector6
	table6 *[TABLE_SIZE]*link6 // 策略使用计算出的索引从这里查询策略

	cloudPlatformLabeler *CloudPlatformLabeler

	maxBucket uint64
	proc      *process.Process
}

func getAclId(ids ...uint32) uint32 {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return 0
}

func NewDdbs(queueCount, level int, mapSize uint32, fastPathDisable bool) TableOperator {
	if level < _LEVEL_MIN || level > _LEVEL_MAX {
		log.Errorf("NewDdbs invalid level %d.", level)
		time.Sleep(time.Second)
		os.Exit(-1)
	}
	ddbs := new(Ddbs)
	ddbs.queueCount = queueCount
	ddbs.level = level
	ddbs.currentLevel = level
	ddbs.FastPathDisable = fastPathDisable
	ddbs.groupIpMap = make(map[uint16][]ipSegment, 1000)
	ddbs.InterestTable.Init()
	ddbs.FastPath.Init(mapSize, queueCount)
	ddbs.table = &[TABLE_SIZE]*link{}
	ddbs.table6 = &[TABLE_SIZE]*link6{}
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Errorf("NewProcess(%d): %v", os.Getpid(), err)
		time.Sleep(time.Second)
		os.Exit(-1)
	}
	ddbs.proc = proc
	return ddbs
}

func (d *Ddbs) UpdateMemoryLimit(memoryLimit uint64) {
	d.memoryLimit = memoryLimit
}

func (d *Ddbs) memoryCheck(size uint64) bool {
	return d.memoryLimit == 0 || d.Current()+size < d.memoryLimit
}

func (d *Ddbs) generateAclBits(acls []*Acl) (uint64, error) {
	aclMemory := uint64(0)
	for _, acl := range acls {
		srcIps := make([]ipSegment, 0, 1)
		dstIps := make([]ipSegment, 0, 1)

		for _, group := range acl.SrcGroups {
			srcIps = append(srcIps, d.groupIpMap[uint16(group)]...)
		}
		for _, group := range acl.DstGroups {
			dstIps = append(dstIps, d.groupIpMap[uint16(group)]...)
		}
		// 当配置策略为ANY->B时，源端为全采集
		if len(srcIps) == 0 {
			srcIps = append(srcIps, emptyIpSegment, emptyIp6Segment)
		}
		// 当配置策略为B->ANY时，目的端为全采集
		if len(dstIps) == 0 {
			dstIps = append(dstIps, emptyIpSegment, emptyIp6Segment)
		}

		srcIpv4Count, srcIpv6Count := 0, 0
		dstIpv4Count, dstIpv6Count := 0, 0
		for _, srcIp := range srcIps {
			if srcIp.isIpv6() {
				srcIpv6Count += 1
			} else {
				srcIpv4Count += 1
			}
		}
		for _, dstIp := range dstIps {
			if dstIp.isIpv6() {
				dstIpv6Count += 1
			} else {
				dstIpv4Count += 1
			}
		}
		memorySize := uint64(_FIELD_NODE_SIZE * srcIpv4Count * dstIpv4Count * len(acl.SrcPortRange) * len(acl.DstPortRange))
		memorySize += uint64(_FIELD6_NODE_SIZE * srcIpv6Count * dstIpv6Count * len(acl.SrcPortRange) * len(acl.DstPortRange))
		if !d.memoryCheck(memorySize) {
			log.Warningf("Memory will exceed limit %d bytes, policy %d probably need memory %d bytes.", d.memoryLimit, acl.Id, memorySize)
			return aclMemory, errors.New(fmt.Sprintf("Memory will exceed limit %d bytes, reconfig process memory limit or optimize policy.",
				d.memoryLimit))
		}
		aclMemory += memorySize

		// 根据策略字段生成对应的bits
		acl.generateMatched(srcIps, dstIps)
		acl.InitPolicy()
	}
	return aclMemory, nil
}

func (d *Ddbs) getVectorSize(acls []*Acl, memoryExceeded bool) int {
	matchedSum := 0
	for _, acl := range acls {
		matchedSum += int(acl.FieldLink.Count) + int(acl.Field6Link.Count)
	}
	limit := _POLICY_LIMIT
	if d.memoryLimit != 0 && d.memoryLimit <= _MEMORY_LIMIT {
		limit = (_POLICY_LIMIT * int(d.memoryLimit)) / _MEMORY_LIMIT
	}
	// 有效策略个数小于阈值后，使用默认内存性能等级
	if matchedSum <= limit && !memoryExceeded && d.currentLevel != d.level {
		log.Warningf("Policy count %d less than limit %d, change memory level to %d.", matchedSum, limit, d.level)
		d.currentLevel = d.level
	}
	vectorSize := 0
	for vectorSize = MASK_VECTOR_MAX_SIZE; vectorSize >= MASK_VECTOR_MIN_SIZE; vectorSize-- {
		if matchedSum>>d.currentLevel >= 1<<vectorSize {
			break
		}
	}
	return vectorSize
}

func abs(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// 初始索引，当比特位越能均分策略该值越小，例如：
// +---+---+------+--------+
// | a | b | base | result |
// -------------------------
// | 0 | 0 | 10   | 10     |
// | 5 | 5 | 10   | 0      |
// | 3 | 3 | 10   | 4      |
// | 4 | 5 | 10   | 2      |
// | 1 | 9 | 10   | 8      |
// -------------------------
func calcIndex(a, b, base int) int {
	if a == 0 && b == 0 {
		return base
	}
	return abs(a, b) + (base - (a + b))
}

func (d *Ddbs) getSortTableIndex(matched0, matched1, base int) int {
	index := calcIndex(matched0, matched1, base)
	if index > math.MaxInt16 {
		// 当index非常大时我们需要建立一个多对一的映射关系将其映射到数组的后32767位中
		//
		// 数组前部分存未映射的数据，数组后部分存映射的数据
		n := (base >> 15) + 1
		index = (index / n) + math.MaxInt16
	}
	return index
}

func (d *Ddbs) generateSortTable(acls []*Acl) *[math.MaxUint16][]int {
	base := 0
	for _, acl := range acls {
		base += int(acl.FieldLink.Count)
	}
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]int{}
	for i := 0; i < MATCHED_FIELD_BITS_LEN; i++ {
		matched0, matched1 := 0, 0
		for _, acl := range acls {
			for item := acl.FieldLink.Head; item != nil; item = item.Next {
				if item.MatchedMask.IsBitZero(i) {
					continue
				}
				if item.Matched.IsBitZero(i) {
					matched0++
				} else {
					matched1++
				}
			}
		}
		index := d.getSortTableIndex(matched0, matched1, base)
		table[index] = append(table[index], i)
	}
	return &table
}

func (d *Ddbs) generateSortTable6(acls []*Acl) *[math.MaxUint16][]int {
	base := 0
	for _, acl := range acls {
		base += int(acl.Field6Link.Count)
	}
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]int{}
	for i := 0; i < MATCHED_FIELD6_BITS_LEN; i++ {
		matched0, matched1 := 0, 0
		for _, acl := range acls {
			for item := acl.Field6Link.Head; item != nil; item = item.Next {
				if item.MatchedMask.IsBitZero(i) {
					continue
				}
				if item.Matched.IsBitZero(i) {
					matched0++
				} else {
					matched1++
				}
			}
		}
		index := d.getSortTableIndex(matched0, matched1, base)
		table[index] = append(table[index], i)
	}
	return &table
}

func (d *Ddbs) generateVectorTable6(acls []*Acl) {
	table := &[TABLE_SIZE]*link6{}
	max := 0
	for _, acl := range acls {
		for node := acl.Field6Link.Head; node != nil; node = node.Next {
			indexs := node.GetAllTableIndex(&d.maskVector6, d.mask6MinBit, d.mask6MaxBit, d.vector6Bits)
			items := make([]Table6Item, len(indexs))
			for j, index := range indexs {
				item := &items[j]
				item.match = &node.Matched
				item.mask = &node.MatchedMask
				item.policy = &acl.policy
				l := table[index]
				if l == nil {
					l = &link6{item, 1}
					table[index] = l
				} else {
					item.next = l.head
					l.head = item
					l.count += 1
				}
				if int(l.count) > max {
					max = int(l.count)
				}
			}
		}
	}
	if uint64(max) > d.maxBucket {
		d.maxBucket = uint64(max)
	}
	d.table6 = table
}

func (d *Ddbs) generateVectorTable(acls []*Acl) {
	table := &[TABLE_SIZE]*link{}
	max := 0
	n := 0
	for _, acl := range acls {
		for node := acl.FieldLink.Head; node != nil; node = node.Next {
			indexs := node.GetAllTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit, d.vectorBits)
			items := make([]TableItem, len(indexs))
			n += len(indexs)
			for j, index := range indexs {
				item := &items[j]
				item.match = &node.Matched
				item.mask = &node.MatchedMask
				item.policy = &acl.policy
				l := table[index]
				if l == nil {
					l = &link{item, 1}
					table[index] = l
				} else {
					item.next = l.head
					l.head = item
					l.count += 1
				}

				if int(l.count) > max {
					max = int(l.count)
				}
			}
		}
	}
	if uint64(max) > d.maxBucket {
		d.maxBucket = uint64(max)
	}
	d.table = table
}

func (d *Ddbs) Current() uint64 {
	mem, err := d.proc.MemoryInfo()
	if err != nil {
		log.Errorf("Get memory info failed: %v, trident restart...", err)
		time.Sleep(time.Second)
		os.Exit(-1)
	}
	return mem.RSS
}

func (d *Ddbs) generateDdbsTable(acls []*Acl) error {
	// 生成策略对应的bits
	aclMemory, err := d.generateAclBits(acls)
	if err != nil {
		return err
	}
	v, v6 := vector{}, vector6{}
	ok := true
	itemCount := uint64(0)
	vectorSize := 0
	for d.currentLevel < _LEVEL_MAX && (!ok || vectorSize == 0) {
		// 当策略个数小于阈值并且是循环第一次执行时，currentLevel会重置为配置值
		// 当检测到当前的currentLevel设置内存占用比较大时，会调整level并重新计算内存直到内存满足预期
		//
		// 内存计算过程中会使用到一些切片，这些切片不是常驻内存但也不会立即释放到系统中，所以内存使用
		// 比计算的结果稍微大一些，如果循环次数多切片内存会占用的更多
		vectorSize = d.getVectorSize(acls, !ok)

		v.generateMaskVector(acls, vectorSize, d.generateSortTable(acls))
		v6.generateMaskVector(acls, vectorSize, d.generateSortTable6(acls))

		memorySize := v.calcVectorTableMemory(acls)
		memorySize += v6.calcVectorTableMemory(acls)
		policyCount := uint64(0)
		for _, acl := range acls {
			policyCount += uint64(acl.FieldLink.Count + acl.Field6Link.Count)
		}
		itemCount = v.itemCount + v6.itemCount
		log.Infof("DDBS memory level %d, policy count %d, item count %d + %d = %d, vector size %d, probably need memory %d bytes.",
			d.currentLevel, policyCount, v.itemCount, v6.itemCount, itemCount,
			vectorSize, memorySize+aclMemory)

		// 内存检查
		// aclMemory已经在generateAclBits函数中申请，包括在d.Current()中。
		ok = d.memoryLimit == 0 || d.Current()+memorySize < d.memoryLimit
		if !ok {
			if d.currentLevel < _LEVEL_MAX && itemCount > policyCount {
				d.currentLevel += 1
				log.Warningf("DDBS memory limit %dB will be exceed, change memory level to %d.", d.memoryLimit, d.currentLevel)
				continue
			}
			return errors.New(fmt.Sprintf("DDBS memory limit (%dB) will be exceed, please enlarge total memory limit or optimize policy.",
				d.memoryLimit))
		}
	}

	d.vector = v
	d.vector6 = v6
	d.generateVectorTable(acls)
	d.generateVectorTable6(acls)
	log.Infof("DDBS bucket max %d, avg %d.", d.maxBucket, itemCount/(1<<vectorSize))
	return nil
}

func (d *Ddbs) addFastPath(endpointData *EndpointData, packet *LookupKey, policyForward, policyBackward *PolicyData) (*EndpointStore, *EndpointData) {
	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)

	// ddbs算法不使用interest相关，这里为加入fastpath做准备
	d.getFastInterestKeys(packet)

	packetEndpointData := d.cloudPlatformLabeler.UpdateEndpointData(endpointStore, packet)
	d.addPortFastPolicy(endpointStore, packetEndpointData, packet, policyForward, policyBackward)
	return endpointStore, packetEndpointData
}

func (d *Ddbs) mergePolicy(packetEndpointData *EndpointData, packet *LookupKey, findPolicy, policyForward, policyBackward *PolicyData) {
	id := getAclId(policyForward.AclId, policyBackward.AclId)
	if id > 0 {
		length := len(policyForward.NpbActions) + len(policyBackward.NpbActions)
		findPolicy.NpbActions = make([]NpbActions, 0, length)
		findPolicy.MergeNpbAction(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
		if packet.HasFeatureFlag(NPB) {
			findPolicy.FormatNpbAction()
			findPolicy.Dedup(packet)
		}
	} else {
		*findPolicy = *INVALID_POLICY_DATA
		d.UnmatchedPacketCount++
	}
}

func (d *Ddbs) getPolicyFromTable(key *MatchedField, direction DirectionType, portPolicy *PolicyData) *PolicyData {
	index := key.GetTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit)
	l := d.table[index]
	if l == nil {
		return portPolicy
	}
	for item := l.head; item != nil; item = item.next {
		if result := key.And(item.mask); result.Equal(item.match) {
			if portPolicy == INVALID_POLICY_DATA {
				portPolicy = new(PolicyData)
			}
			policy := item.policy
			portPolicy.Merge(policy.NpbActions, policy.AclId, direction)
		}
	}
	return portPolicy
}

func (d *Ddbs) getPolicyFromTable6(key *MatchedField6, direction DirectionType, portPolicy *PolicyData) *PolicyData {
	index := key.GetTableIndex(&d.maskVector6, d.mask6MinBit, d.mask6MaxBit)
	l := d.table6[index]
	if l == nil {
		return portPolicy
	}
	for item := l.head; item != nil; item = item.next {
		if result := key.And(item.mask); result.Equal(item.match) {
			if portPolicy == INVALID_POLICY_DATA {
				portPolicy = new(PolicyData)
			}
			policy := item.policy
			portPolicy.Merge(policy.NpbActions, policy.AclId, direction)
		}
	}
	return portPolicy
}

func (d *Ddbs) GetPolicyByFirstPath(packet *LookupKey, findPolicy *PolicyData, endpointData *EndpointData) *EndpointStore {
	packet.GenerateMatchedField(endpointData.SrcInfo.GetL3Epc(), endpointData.DstInfo.GetL3Epc())

	keys := [...]*MatchedField{FORWARD: &packet.ForwardMatched, BACKWARD: &packet.BackwardMatched}
	key6s := [...]*MatchedField6{FORWARD: &packet.ForwardMatched6, BACKWARD: &packet.BackwardMatched6}
	policys := [...]*PolicyData{FORWARD: INVALID_POLICY_DATA, BACKWARD: INVALID_POLICY_DATA}

	if len(packet.Src6Ip) == 16 {
		for _, direction := range []DirectionType{FORWARD, BACKWARD} {
			key := key6s[direction]
			policys[direction] = d.getPolicyFromTable6(key, direction, policys[direction])
		}
	} else {
		for _, direction := range []DirectionType{FORWARD, BACKWARD} {
			key := keys[direction]
			policys[direction] = d.getPolicyFromTable(key, direction, policys[direction])
		}
	}

	endpointStore, packetEndpointData := d.addFastPath(endpointData, packet, policys[FORWARD], policys[BACKWARD])
	d.mergePolicy(packetEndpointData, packet, findPolicy, policys[FORWARD], policys[BACKWARD])

	d.FirstPathHit++
	if aclHit := uint32(len(findPolicy.NpbActions)); d.AclHitMax < aclHit {
		d.AclHitMax = aclHit
	}
	return endpointStore
}

func (d *Ddbs) checkAcl(acl *Acl, check ...bool) bool {
	if len(check) > 0 && !check[0] {
		return false
	}

	// 若策略的资源组中任何一个未在云平台数据和IP资源组中查找到，算作无效策略
	for _, group := range acl.SrcGroups {
		if len(d.groupIpMap[uint16(group)]) == 0 {
			log.Warningf("invalid acl by group(%d): %s\n", group, acl)
			return true
		}
	}

	for _, group := range acl.DstGroups {
		if len(d.groupIpMap[uint16(group)]) == 0 {
			log.Warningf("invalid acl by group(%d): %s\n", group, acl)
			return true
		}
	}
	return false
}

func (d *Ddbs) UpdateAcls(acls []*Acl, check ...bool) error {
	generateAcls := make([]*Acl, 0, len(acls))

	for _, acl := range acls {
		invalid := d.checkAcl(acl, check...)
		if invalid {
			continue
		}
		acl.Reset()
		generateAcls = append(generateAcls, acl)
	}

	// 生成Ddbs查询表
	err := d.generateDdbsTable(generateAcls)
	if err != nil {
		return err
	}
	d.RawAcls = acls
	// 生成策略InterestMap
	d.GenerateInterestMaps(generateAcls)
	return nil
}

func (d *Ddbs) GetHitStatus() (uint64, uint64) {
	return d.FirstPathHit, d.FastPathHit
}

func (d *Ddbs) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(d.cloudPlatformLabeler.macTable.macMap)),
		EpcIpTable: uint32(len(d.cloudPlatformLabeler.epcIpTable.epcIpMap)),
	}
	for i := MIN_MASK_LEN; i < MAX_MASK_LEN; i++ {
		counter.IpTable += uint32(len(d.cloudPlatformLabeler.ipTables[i].ipMap))
	}

	counter.Acl += uint32(len(d.RawAcls))
	counter.FirstHit = d.FirstPathHit
	counter.FastHit = d.FastPathHit
	counter.AclHitMax = d.AclHitMax
	d.FirstPathHit = 0
	d.FastPathHit = 0
	d.AclHitMax = 0
	counter.FastPathMacCount = d.FastPathMacCount
	counter.FastPathPolicyCount = d.FastPathPolicyCount
	counter.UnmatchedPacketCount = d.UnmatchedPacketCount
	counter.FirstPathItems = d.vector.itemCount + d.vector6.itemCount
	counter.FirstPathMaxBucket = uint32(d.maxBucket)
	for i := 0; i < d.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			maps := d.FastPortPolicyMaps[i][j]
			if maps != nil {
				counter.FastPath += uint32(maps.Size())
			}
		}
	}
	return counter
}

func (d *Ddbs) FlushAcls() {
	d.FastPath.FlushAcls()
	d.UnmatchedPacketCount = 0
}

func (d *Ddbs) AddAcl(acl *Acl) {
	acls := d.RawAcls

	acls = append(acls, acl)
	d.UpdateAcls(acls)
	d.FlushAcls()
}

func (d *Ddbs) DelAcl(id int) {
	acls := d.RawAcls

	if id > len(acls) || id <= 0 {
		return
	}

	index := id - 1
	if id == len(acls) {
		d.UpdateAcls(acls[:index])
		d.FlushAcls()
	} else {
		newAcls := acls[0:index]
		newAcls = append(newAcls, acls[index+1:]...)
		d.UpdateAcls(newAcls)
		d.FlushAcls()
	}
}

func (d *Ddbs) GetAcl() []*Acl {
	return d.RawAcls
}

func (d *Ddbs) SetCloudPlatform(cloudPlatformLabeler *CloudPlatformLabeler) {
	d.cloudPlatformLabeler = cloudPlatformLabeler
}

func (d *Ddbs) generateGroupIpMap(data []*IpGroupData) {
	groupIpMap := make(map[uint16][]ipSegment, 1000)
	for _, data := range data {
		if data.Id != 0 {
			groupId := uint16(data.Id & 0xffff)
			for _, ips := range data.Ips {
				if segment, ok := newIpSegment(ips, uint16(data.EpcId&0xffff)); ok {
					groupIpMap[groupId] = append(groupIpMap[groupId], segment)
				}
			}
		}
	}
	d.groupIpMap = groupIpMap
}

func (d *Ddbs) UpdateInterfaceData(data []PlatformData) {
	d.GenerateIpNetmaskMapFromPlatformData(data)
}

func (d *Ddbs) UpdateIpGroupData(data []*IpGroupData) {
	d.generateGroupIpMap(data)
	d.GenerateIpNetmaskMapFromIpGroupData(data)
}

func (d *Ddbs) UpdateCidr(data []*Cidr) {
	d.cloudPlatformLabeler.UpdateCidr(data)
	d.GenerateIpNetmaskMapFromCidrData(data)
}

func (d *Ddbs) GetPolicyByFastPath(packet *LookupKey, policy *PolicyData) *EndpointStore {
	if d.FastPathDisable {
		return nil
	}

	var endpoint *EndpointStore
	var portPolicy *PolicyData

	d.getFastInterestKeys(packet)
	if endpoint, portPolicy = d.getPortFastPolicy(packet); portPolicy == nil {
		return nil
	}

	*policy = *portPolicy
	if packet.HasFeatureFlag(NPB) {
		// Dedup会修改策略
		policy.Dedup(packet)
	}

	if policy.AclId == 0 {
		d.UnmatchedPacketCount++
	}

	d.FastPathHit++
	return endpoint
}
