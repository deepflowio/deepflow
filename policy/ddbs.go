package policy

import (
	"math"
	"runtime"
	"sort"
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type TableItem struct {
	match, mask MatchedField

	policy *PolicyRawData
}

const (
	MASK_VECTOR_SIZE = 10
	TABLE_SIZE       = 1 << MASK_VECTOR_SIZE
)

type Ddbs struct {
	FastPath
	InterestTable
	AclGidMap
	groupMacMap map[uint16][]uint32
	groupIpMap  map[uint16][]ipSegment

	FastPathDisable bool
	queueCount      int

	RawAcls []*Acl

	FirstPathHit, FirstPathHitTick uint64
	AclHitMax                      uint32
	UnmatchedPacketCount           uint64

	vectorBits             []int
	maskMinBit, maskMaxBit int
	maskVector             MatchedField              // 根据所有策略计算出的M-Vector, 用于创建查询table
	table                  *[TABLE_SIZE][]*TableItem // 策略使用计算出的索引从这里查询策略

	cloudPlatformLabeler *CloudPlatformLabeler
}

func NewDdbs(queueCount int, mapSize uint32, fastPathDisable bool) TableOperator {
	ddbs := new(Ddbs)
	ddbs.queueCount = queueCount
	ddbs.FastPathDisable = fastPathDisable
	ddbs.groupMacMap = make(map[uint16][]uint32, 1000)
	ddbs.groupIpMap = make(map[uint16][]ipSegment, 1000)
	ddbs.AclGidMap.Init()
	ddbs.InterestTable.Init()
	ddbs.FastPath.Init(mapSize, queueCount, ddbs.AclGidMap.SrcGroupAclGidMaps, ddbs.AclGidMap.DstGroupAclGidMaps)
	ddbs.table = &[TABLE_SIZE][]*TableItem{}
	return ddbs
}

func (d *Ddbs) GenerateGroupAclGidMaps(acls []*Acl) {
	d.AclGidMap.GenerateGroupAclGidMaps(acls, false)
	d.FastPath.UpdateGroupAclGidMaps(d.AclGidMap.SrcGroupAclGidMaps, d.AclGidMap.DstGroupAclGidMaps)
}

func (d *Ddbs) generateAclBits(acls []*Acl) {
	for _, acl := range acls {
		srcMac := make([]uint32, 0, 8)
		dstMac := make([]uint32, 0, 8)
		srcIps := make([]ipSegment, 0, 8)
		dstIps := make([]ipSegment, 0, 8)

		for _, group := range acl.SrcGroups {
			srcMac = append(srcMac, d.groupMacMap[uint16(group)]...)
			srcIps = append(srcIps, d.groupIpMap[uint16(group)]...)
		}
		for _, group := range acl.DstGroups {
			dstMac = append(dstMac, d.groupMacMap[uint16(group)]...)
			dstIps = append(dstIps, d.groupIpMap[uint16(group)]...)
		}
		// 当配置策略为ANY->B时，源端为全采集
		if len(srcMac) == 0 && len(srcIps) == 0 {
			srcMac = append(srcMac, 0)
		}
		// 当配置策略为B->ANY时，目的端为全采集
		if len(dstMac) == 0 && len(dstIps) == 0 {
			dstMac = append(dstMac, 0)
		}
		// 根据策略字段生成对应的bits
		acl.generateMatched(srcMac, dstMac, srcIps, dstIps)
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

func (d *Ddbs) generateMaskVector(acls []*Acl) {
	table := d.generateSortTable(acls)
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
	d.maskVector.SetBits(vectorBits...)
	d.maskMinBit = vectorBits[0]
	d.maskMaxBit = vectorBits[vectorSize-1]
	d.vectorBits = vectorBits
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
	d.generateMaskVector(acls)
	d.generateVectorTable(acls)
}

func (d *Ddbs) addFastPath(endpointData *EndpointData, packet *LookupKey, policyForward, policyBackward, vlanPolicy *PolicyData) (*EndpointStore, *EndpointData) {
	srcEpc := endpointData.SrcInfo.GetEpc()
	dstEpc := endpointData.DstInfo.GetEpc()
	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)

	d.cloudPlatformLabeler.RemoveAnonymousGroupIds(endpointStore, packet)
	packetEndpointData := d.cloudPlatformLabeler.UpdateEndpointData(endpointStore, packet)
	mapsForward, mapsBackward := d.addPortFastPolicy(endpointStore, packetEndpointData, srcEpc, dstEpc, packet, policyForward, policyBackward)

	if packet.Vlan > 0 {
		d.addVlanFastPolicy(srcEpc, dstEpc, packet, vlanPolicy, endpointData, mapsForward, mapsBackward)
	}
	return endpointStore, packetEndpointData
}

func (d *Ddbs) mergePolicy(packetEndpointData *EndpointData, packet *LookupKey, policyForward, policyBackward, vlanPolicy *PolicyData) *PolicyData {
	findPolicy := INVALID_POLICY_DATA
	id := getAclId(vlanPolicy.ACLID, policyForward.ACLID, policyBackward.ACLID)
	if id > 0 {
		findPolicy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			length := len(policyForward.AclActions) + len(policyBackward.AclActions) + len(vlanPolicy.AclActions)
			findPolicy.AclActions = make([]AclAction, 0, length)
			findPolicy.MergeAclAction(append(vlanPolicy.AclActions, append(policyForward.AclActions, policyBackward.AclActions...)...), id)
			findPolicy.AddAclGidBitmaps(packet, false, d.AclGidMap.SrcGroupAclGidMaps[packet.Tap], d.AclGidMap.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			length := len(policyForward.NpbActions) + len(policyBackward.NpbActions)
			findPolicy.NpbActions = make([]NpbAction, 0, length)
			findPolicy.MergeNpbAction(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
			findPolicy.FormatNpbAction()
			findPolicy.NpbActions = findPolicy.CheckNpbAction(packet, packetEndpointData)
		}
	} else {
		atomic.AddUint64(&d.UnmatchedPacketCount, 1)
	}
	return findPolicy
}

func (d *Ddbs) getPolicyFromTable(key *MatchedField, direction DirectionType, portPolicy *PolicyData, vlanPolicy *PolicyData) (*PolicyData, *PolicyData) {
	index := key.GetTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit)
	for _, item := range d.table[index] {
		if result := key.And(&item.mask); result.Equal(&item.match) {
			if portPolicy == INVALID_POLICY_DATA {
				portPolicy = new(PolicyData)
			}
			policy := item.policy
			portPolicy.Merge(policy.AclActions, policy.NpbActions, policy.ACLID, direction)
			if item.match.Get(MATCHED_VLAN) > 0 {
				if vlanPolicy == INVALID_POLICY_DATA {
					vlanPolicy = new(PolicyData)
				}
				vlanPolicy.Merge(policy.AclActions, policy.NpbActions, policy.ACLID, direction)
			}
		}
	}
	return portPolicy, vlanPolicy
}

func (d *Ddbs) initGroupIds(endpointData *EndpointData, packet *LookupKey) {
	packet.SrcAllGroupIds = make([]uint16, 0, len(endpointData.SrcInfo.GroupIds))
	packet.DstAllGroupIds = make([]uint16, 0, len(endpointData.DstInfo.GroupIds))
	for _, id := range endpointData.SrcInfo.GroupIds {
		packet.SrcAllGroupIds = append(packet.SrcAllGroupIds, uint16(FormatGroupId(id)&0xffff))
	}
	for _, id := range endpointData.DstInfo.GroupIds {
		packet.DstAllGroupIds = append(packet.DstAllGroupIds, uint16(FormatGroupId(id)&0xffff))
	}
}

func (d *Ddbs) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) (*EndpointStore, *PolicyData) {
	// ddbs不需要资源组相关的优化，只使用端口协议的优化
	d.getFastInterestKeys(packet)
	d.initGroupIds(endpointData, packet)
	packet.GenerateMatchedField(endpointData.SrcInfo.GetL3Epc(), endpointData.DstInfo.GetL3Epc())

	vlanPolicy := INVALID_POLICY_DATA
	keys := [...]*MatchedField{FORWARD: &packet.ForwardMatched, BACKWARD: &packet.BackwardMatched}
	policys := [...]*PolicyData{FORWARD: INVALID_POLICY_DATA, BACKWARD: INVALID_POLICY_DATA}

	for _, direction := range []DirectionType{FORWARD, BACKWARD} {
		key := keys[direction]
		policys[direction], vlanPolicy = d.getPolicyFromTable(key, direction, policys[direction], vlanPolicy)
	}

	endpointStore, packetEndpointData := d.addFastPath(endpointData, packet, policys[FORWARD], policys[BACKWARD], vlanPolicy)
	findPolicy := d.mergePolicy(packetEndpointData, packet, policys[FORWARD], policys[BACKWARD], vlanPolicy)

	atomic.AddUint64(&d.FirstPathHit, 1)
	atomic.AddUint64(&d.FirstPathHitTick, 1)
	aclHitMax := atomic.LoadUint32(&d.AclHitMax)
	if aclHit := uint32(len(findPolicy.AclActions) + len(findPolicy.NpbActions)); aclHitMax < aclHit {
		atomic.CompareAndSwapUint32(&d.AclHitMax, aclHitMax, aclHit)
	}
	return endpointStore, findPolicy
}

func (d *Ddbs) UpdateAcls(acls []*Acl) {
	d.RawAcls = acls

	generateAcls := make([]*Acl, 0, len(acls))
	for _, acl := range acls {
		// acl需要根据groupIdMaps更新里面的NpbActions
		if len(acl.NpbActions) > 0 {
			groupType := RESOURCE_GROUP_TYPE_IP | RESOURCE_GROUP_TYPE_DEV
			for _, id := range append(acl.SrcGroups, acl.DstGroups...) {
				// 带NPB的acl，资源组类型为全DEV或全IP两种情况
				if id != 0 && d.groupIdMaps[id] != 0 {
					groupType = d.groupIdMaps[id]
				}
				break
			}
			for index, _ := range acl.NpbActions {
				acl.NpbActions[index].AddResourceGroupType(groupType)
			}
		}
		generateAcls = append(generateAcls, acl)
	}

	// 生成策略InterestMap,更新策略
	d.GenerateInterestMaps(generateAcls)
	d.GenerateGroupAclGidMaps(generateAcls)
	// 生成Ddbs查询表
	d.generateDdbsTable(generateAcls)
}

func (d *Ddbs) GetHitStatus() (uint64, uint64) {
	return atomic.LoadUint64(&d.FirstPathHit), atomic.LoadUint64(&d.FastPathHit)
}

func (d *Ddbs) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(d.cloudPlatformLabeler.macTable.macMap)),
		EpcIpTable: uint32(len(d.cloudPlatformLabeler.epcIpTable.epcIpMap)),
	}
	for i := MIN_MASK_LEN; i < MAX_MASK_LEN; i++ {
		counter.IpTable += uint32(len(d.cloudPlatformLabeler.ipTables[i].ipMap))
	}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		counter.ArpTable += uint32(len(d.cloudPlatformLabeler.arpTable[i]))
	}

	counter.Acl += uint32(len(d.RawAcls))
	counter.FirstHit = atomic.SwapUint64(&d.FirstPathHitTick, 0)
	counter.FastHit = atomic.SwapUint64(&d.FastPathHitTick, 0)
	counter.AclHitMax = atomic.SwapUint32(&d.AclHitMax, 0)
	counter.FastPathMacCount = atomic.LoadUint32(&d.FastPathMacCount)
	counter.FastPathPolicyCount = atomic.LoadUint32(&d.FastPathPolicyCount)
	counter.UnmatchedPacketCount = atomic.LoadUint64(&d.UnmatchedPacketCount)
	for i := 0; i < d.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			maps := d.FastPolicyMaps[i][j]
			mapsMini := d.FastPolicyMapsMini[i][j]
			if maps != nil {
				counter.FastPath += uint32(maps.Len())
			}
			if mapsMini != nil {
				counter.FastPath += uint32(mapsMini.Len())
			}
		}
	}
	return counter
}

func (d *Ddbs) FlushAcls() {
	d.FastPath.FlushAcls()
	atomic.StoreUint64(&d.UnmatchedPacketCount, 0)
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

func (d *Ddbs) generateGroupMacMap(data []*PlatformData) {
	groupMacMap := make(map[uint16][]uint32, 1000)
	for _, data := range data {
		for _, group := range data.GroupIds {
			groupId := uint16(group & 0xffff)
			groupMacMap[groupId] = append(groupMacMap[groupId], uint32(data.Mac&0xffffffff))
		}
	}
	d.groupMacMap = groupMacMap
}

func (d *Ddbs) generateGroupIpMap(data []*IpGroupData) {
	groupIpMap := make(map[uint16][]ipSegment, 1000)
	for _, data := range data {
		if data.Id != 0 {
			groupId := uint16(data.Id & 0xffff)
			for _, ips := range data.Ips {
				groupIpMap[groupId] = append(groupIpMap[groupId], newIpSegment(ips, uint16(data.EpcId&0xffff)))
			}
		}
	}
	d.groupIpMap = groupIpMap
}

func (d *Ddbs) UpdateInterfaceData(data []*PlatformData) {
	d.GenerateIpNetmaskMapFromPlatformData(data)
	d.GenerateGroupIdMapByPlatformData(data)
	d.generateGroupMacMap(data)
}

func (d *Ddbs) UpdateIpGroupData(data []*IpGroupData) {
	d.GenerateIpNetmaskMapFromIpGroupData(data)
	d.GenerateGroupIdMapByIpGroupData(data)
	d.generateGroupIpMap(data)
}

func (d *Ddbs) GetPolicyByFastPath(packet *LookupKey) (*EndpointStore, *PolicyData) {
	if d.FastPathDisable {
		return nil, nil
	}

	var endpoint *EndpointStore
	var portPolicy *PolicyData
	vlanPolicy, policy := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if maps := d.getVlanAndPortMap(packet, FORWARD, false, nil); maps != nil {
		srcEpc, dstEpc := d.getFastEpcs(maps, packet)
		// NOTE：会改变packet参数，但firstPath同样需要getFastInterestKeys，所以无影响
		d.getFastInterestKeys(packet)
		if endpoint, portPolicy = d.getFastPortPolicy(maps, srcEpc, dstEpc, packet); portPolicy == nil {
			return nil, nil
		}
		if packet.Vlan > 0 && packet.HasFeatureFlag(NPM) {
			if vlanPolicy = d.getFastVlanPolicy(maps, srcEpc, dstEpc, packet); vlanPolicy == nil {
				return nil, nil
			}
		}
	}
	if vlanPolicy.ACLID == 0 {
		policy = portPolicy
	} else if portPolicy.ACLID == 0 {
		policy = vlanPolicy
	} else {
		id := getAclId(vlanPolicy.ACLID, portPolicy.ACLID)
		policy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			d.initGroupIds(endpoint.Endpoints, packet)
			policy.AclActions = make([]AclAction, 0, len(vlanPolicy.AclActions)+len(portPolicy.AclActions))
			policy.MergeAclAction(append(vlanPolicy.AclActions, portPolicy.AclActions...), id)
			policy.AddAclGidBitmaps(packet, false, d.AclGidMap.SrcGroupAclGidMaps[packet.Tap], d.AclGidMap.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			policy.NpbActions = make([]NpbAction, 0, len(portPolicy.NpbActions))
			policy.MergeNpbAction(portPolicy.NpbActions, id)
			policy.FormatNpbAction()
		}
	}

	if policy != nil && endpoint != nil {
		policy = policy.CheckNpbPolicy(packet, endpoint.Endpoints)
	}

	if policy != nil && policy.ACLID == 0 {
		atomic.AddUint64(&d.UnmatchedPacketCount, 1)
	}

	atomic.AddUint64(&d.FastPathHit, 1)
	atomic.AddUint64(&d.FastPathHitTick, 1)
	return endpoint, policy
}
