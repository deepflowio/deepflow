package policy

import (
	"math"
	"runtime"
	"sort"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type Table6Item struct {
	match, mask MatchedField6

	policy *PolicyData
}

type TableItem struct {
	match, mask MatchedField

	policy *PolicyData
}

const (
	MASK_VECTOR_SIZE = 10
	TABLE_SIZE       = 1 << MASK_VECTOR_SIZE
)

type Ddbs struct {
	FastPath
	InterestTable
	groupIpMap map[uint16][]ipSegment

	FastPathDisable bool
	queueCount      int

	RawAcls []*Acl

	FirstPathHit         uint64
	AclHitMax            uint32
	UnmatchedPacketCount uint64

	// ipv4
	maskMinBit, maskMaxBit int
	vectorBits             []int
	maskVector             MatchedField              // 根据所有策略计算出的M-Vector, 用于创建查询table
	table                  *[TABLE_SIZE][]*TableItem // 策略使用计算出的索引从这里查询策略
	// ipv6
	mask6MinBit, mask6MaxBit int
	vector6Bits              []int
	maskVector6              MatchedField6              // 根据所有策略计算出的M-Vector, 用于创建查询table
	table6                   *[TABLE_SIZE][]*Table6Item // 策略使用计算出的索引从这里查询策略

	cloudPlatformLabeler *CloudPlatformLabeler
}

func getAclId(ids ...uint32) uint32 {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return 0
}

func NewDdbs(queueCount int, mapSize uint32, fastPathDisable bool) TableOperator {
	ddbs := new(Ddbs)
	ddbs.queueCount = queueCount
	ddbs.FastPathDisable = fastPathDisable
	ddbs.groupIpMap = make(map[uint16][]ipSegment, 1000)
	ddbs.InterestTable.Init()
	ddbs.FastPath.Init(mapSize, queueCount)
	ddbs.table = &[TABLE_SIZE][]*TableItem{}
	ddbs.table6 = &[TABLE_SIZE][]*Table6Item{}
	return ddbs
}

func (d *Ddbs) generateAclBits(acls []*Acl) {
	for _, acl := range acls {
		srcIps := make([]ipSegment, 0, 8)
		dstIps := make([]ipSegment, 0, 8)

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
		// 根据策略字段生成对应的bits
		acl.generateMatched(srcIps, dstIps)
		acl.InitPolicy()
	}
}

func abs(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func (d *Ddbs) getVectorSize(aclNum int) int {
	vectorSize := MASK_VECTOR_SIZE
	if aclNum < 100 {
		vectorSize = MASK_VECTOR_SIZE - 4
	} else if aclNum < 300 {
		vectorSize = MASK_VECTOR_SIZE - 3
	} else if aclNum < 500 {
		vectorSize = MASK_VECTOR_SIZE - 2
	} else if aclNum < 10240 {
		vectorSize = MASK_VECTOR_SIZE - 1
	}
	return vectorSize
}

func (d *Ddbs) getSortTableIndex(matched0, matched1, base int) int {
	index := abs(matched0, matched1)
	// index计算引入影响因子和影响百分比，将这样的位（mathed0/1: 0, 1 base: 2000）排在后面
	perCent := 1 - float32(matched0+matched1)/float32(base)
	factor := float32(base / 2)
	if base > math.MaxUint16 {
		factor = float32(math.MaxUint16 / 2)
	}
	index += int(factor * perCent)
	if index >= math.MaxUint16 || (matched0 == 0 && matched1 == 0) {
		index = math.MaxUint16 - 1
	}
	return index
}

func (d *Ddbs) generateSortTable(acls []*Acl) *[math.MaxUint16][]int {
	base := 0
	for _, acl := range acls {
		base += len(acl.AllMatched)
	}
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]int{}
	for i := 0; i < MATCHED_FIELD_BITS_LEN; i++ {
		matched0, matched1 := 0, 0
		for _, acl := range acls {
			for j := 0; j < len(acl.AllMatched); j++ {
				if acl.AllMatchedMask[j].IsBitZero(i) {
					continue
				}
				if acl.AllMatched[j].IsBitZero(i) {
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
		base += len(acl.AllMatched6)
	}
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]int{}
	for i := 0; i < MATCHED_FIELD6_BITS_LEN; i++ {
		matched0, matched1 := 0, 0
		for _, acl := range acls {
			for j := 0; j < len(acl.AllMatched6); j++ {
				if acl.AllMatched6Mask[j].IsBitZero(i) {
					continue
				}
				if acl.AllMatched6[j].IsBitZero(i) {
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

func (d *Ddbs) generateMaskVector(acls []*Acl, isIpv6 bool) {
	var table *[math.MaxUint16][]int
	if isIpv6 {
		table = d.generateSortTable6(acls)
	} else {
		table = d.generateSortTable(acls)
	}
	vectorSize := d.getVectorSize(len(acls))
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
	if isIpv6 {
		d.mask6MinBit = vectorBits[0]
		d.mask6MaxBit = vectorBits[vectorSize-1]
		d.maskVector6.SetBits(vectorBits...)
		d.vector6Bits = vectorBits
	} else {
		d.mask6MinBit = vectorBits[0]
		d.mask6MaxBit = vectorBits[vectorSize-1]
		d.maskVector.SetBits(vectorBits...)
		d.vectorBits = vectorBits
	}
}

func (d *Ddbs) generateVectorTable6(acls []*Acl) {
	table := &[TABLE_SIZE][]*Table6Item{}
	for _, acl := range acls {
		for i, match := range acl.AllMatched6 {
			index := match.GetAllTableIndex(&d.maskVector6, &acl.AllMatched6Mask[i], d.mask6MinBit, d.mask6MaxBit, d.vector6Bits)
			for _, index := range index {
				table[index] = append(table[index], &Table6Item{match, acl.AllMatched6Mask[i], &acl.policy})
			}
		}
	}
	d.table6 = table
	runtime.GC()
}

func (d *Ddbs) generateVectorTable(acls []*Acl) {
	table := &[TABLE_SIZE][]*TableItem{}
	for _, acl := range acls {
		for i, match := range acl.AllMatched {
			index := match.GetAllTableIndex(&d.maskVector, &acl.AllMatchedMask[i], d.maskMinBit, d.maskMaxBit, d.vectorBits)
			for _, index := range index {
				table[index] = append(table[index], &TableItem{match, acl.AllMatchedMask[i], &acl.policy})
			}
		}
	}
	d.table = table
	runtime.GC()
}

func (d *Ddbs) generateDdbsTable(acls []*Acl) {
	// 生成策略对应的bits
	d.generateAclBits(acls)
	// ipv4
	d.generateMaskVector(acls, false)
	d.generateVectorTable(acls)
	// ipv6
	d.generateMaskVector(acls, true)
	d.generateVectorTable6(acls)
}

func (d *Ddbs) addFastPath(endpointData *EndpointData, packet *LookupKey, policyForward, policyBackward *PolicyData) (*EndpointStore, *EndpointData) {
	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)

	packetEndpointData := d.cloudPlatformLabeler.UpdateEndpointData(endpointStore, packet)
	d.addPortFastPolicy(endpointStore, packetEndpointData, packet, policyForward, policyBackward)
	return endpointStore, packetEndpointData
}

func (d *Ddbs) mergePolicy(packetEndpointData *EndpointData, packet *LookupKey, findPolicy, policyForward, policyBackward *PolicyData) {
	id := getAclId(policyForward.AclId, policyBackward.AclId)
	if id > 0 {
		if packet.HasFeatureFlag(NPM) {
			length := len(policyForward.AclActions) + len(policyBackward.AclActions)
			findPolicy.AclActions = make([]AclAction, 0, length)
			findPolicy.MergeAclAction(append(policyForward.AclActions, policyBackward.AclActions...), id)
		}
		if packet.HasFeatureFlag(NPB) {
			length := len(policyForward.NpbActions) + len(policyBackward.NpbActions)
			findPolicy.NpbActions = make([]NpbActions, 0, length)
			findPolicy.MergeNpbAction(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
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
	for _, item := range d.table[index] {
		if result := key.And(&item.mask); result.Equal(&item.match) {
			if portPolicy == INVALID_POLICY_DATA {
				portPolicy = new(PolicyData)
			}
			policy := item.policy
			portPolicy.Merge(policy.AclActions, policy.NpbActions, policy.AclId, direction)
		}
	}
	return portPolicy
}

func (d *Ddbs) getPolicyFromTable6(key *MatchedField6, direction DirectionType, portPolicy *PolicyData) *PolicyData {
	index := key.GetTableIndex(&d.maskVector6, d.mask6MinBit, d.mask6MaxBit)
	for _, item := range d.table6[index] {
		if result := key.And(&item.mask); result.Equal(&item.match) {
			if portPolicy == INVALID_POLICY_DATA {
				portPolicy = new(PolicyData)
			}
			policy := item.policy
			portPolicy.Merge(policy.AclActions, policy.NpbActions, policy.AclId, direction)
		}
	}
	return portPolicy
}

func (d *Ddbs) GetPolicyByFirstPath(packet *LookupKey, findPolicy *PolicyData, endpointData *EndpointData) *EndpointStore {
	// ddbs不需要资源组相关的优化，只使用端口协议的优化
	d.getFastInterestKeys(packet)
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
	if aclHit := uint32(len(findPolicy.AclActions) + len(findPolicy.NpbActions)); d.AclHitMax < aclHit {
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

func (d *Ddbs) UpdateAcls(acls []*Acl, check ...bool) {
	d.RawAcls = acls
	generateAcls := make([]*Acl, 0, len(acls))

	for _, acl := range acls {
		invalid := d.checkAcl(acl, check...)
		if invalid {
			continue
		}
		acl.Reset()
		generateAcls = append(generateAcls, acl)
	}

	// 生成策略InterestMap,更新策略
	d.GenerateInterestMaps(generateAcls)
	// 生成Ddbs查询表
	d.generateDdbsTable(generateAcls)
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

func (d *Ddbs) UpdateInterfaceData(data []*PlatformData) {
	d.GenerateIpNetmaskMapFromPlatformData(data)
}

func (d *Ddbs) UpdateIpGroupData(data []*IpGroupData) {
	d.GenerateIpNetmaskMapFromIpGroupData(data)
	d.generateGroupIpMap(data)
}

func (d *Ddbs) UpdateCidr(data []*Cidr) {
	d.cloudPlatformLabeler.UpdateCidr(data)
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
