package policy

import (
	"math"
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type TableItem struct {
	match, mask MatchedField

	aclAction  []AclAction
	npbActions []NpbAction
	aclID      ACLID
}

const (
	MASK_VECTOR_SIZE = 10
	TABLE_SIZE       = 1 << 10
)

type Ddbs struct {
	FastPath
	InterestTable
	AclGidMap

	FastPathDisable bool
	queueCount      int

	RawAcls []*Acl

	FirstPathHit, FirstPathHitTick uint64
	AclHitMax                      uint32
	UnmatchedPacketCount           uint64

	maskMinBit, maskMaxBit int
	maskVector             MatchedField            // 根据所有策略计算出的M-Vector, 用于创建查询table
	table                  [TABLE_SIZE][]TableItem // 策略使用计算出的索引从这里查询策略

	cloudPlatformLabeler *CloudPlatformLabeler
}

func NewDdbs(queueCount int, mapSize uint32, fastPathDisable bool) TableOperator {
	ddbs := new(Ddbs)
	ddbs.queueCount = queueCount
	ddbs.AclGidMap.Init()
	ddbs.FastPathDisable = fastPathDisable
	ddbs.InterestTable.Init()
	ddbs.FastPath.Init(mapSize, queueCount, ddbs.AclGidMap.SrcGroupAclGidMaps, ddbs.AclGidMap.DstGroupAclGidMaps)
	return ddbs
}

func (d *Ddbs) GenerateGroupAclGidMaps(acls []*Acl) {
	d.AclGidMap.GenerateGroupAclGidMaps(acls)
	d.FastPath.UpdateGroupAclGidMaps(d.AclGidMap.SrcGroupAclGidMaps, d.AclGidMap.DstGroupAclGidMaps)
}

func (d *Ddbs) generateAclBits(acls []*Acl) {
	for _, acl := range acls {
		if len(acl.SrcGroupRelations) == 0 {
			acl.SrcGroupRelations = append(acl.SrcGroupRelations, 0)
		}
		if len(acl.DstGroupRelations) == 0 {
			acl.DstGroupRelations = append(acl.DstGroupRelations, 0)
		}
		if len(acl.SrcPortRange) == 0 {
			acl.SrcPortRange = append(acl.SrcPortRange, NewPortRange(0, 0))
		}
		if len(acl.DstPortRange) == 0 {
			acl.DstPortRange = append(acl.DstPortRange, NewPortRange(0, 0))
		}
		if len(acl.SrcPorts) == 0 {
			acl.SrcPorts = append(acl.SrcPorts, 0)
		}
		if len(acl.DstPorts) == 0 {
			acl.DstPorts = append(acl.DstPorts, 0)
		}

		// 根据策略字段生成对应的bits
		acl.generateMatched()
	}
}

func abs(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func (d *Ddbs) generateMaskVector(acls []*Acl) {
	// 计算对应bits匹配0和1的策略差值
	table := [math.MaxUint16][]int{}
	for i := 0; i < MATCHED_FIELD_BITS_LEN; i++ {
		matched0, matched1 := 0, 0
		for _, acl := range acls {
			if acl.MatchedMask.IsBitZero(i) {
				matched0 += len(acl.AllMatcheds)
				matched1 += len(acl.AllMatcheds)
				continue
			}
			for j := 0; j < len(acl.AllMatcheds); j++ {
				if acl.AllMatcheds[j].IsBitZero(i) {
					matched0++
				} else {
					matched1++
				}
			}
		}

		index := abs(matched0, matched1)
		table[index] = append(table[index], i)
	}

	vectorBits := make([]int, 0, MASK_VECTOR_SIZE)
	// 使用对应差值最小的10个bit位做为MaskVector
	for i := 0; i < math.MaxUint16 && len(vectorBits) < MASK_VECTOR_SIZE; i++ {
		for _, bitOffset := range table[i] {
			vectorBits = append(vectorBits, bitOffset)
			if len(vectorBits) >= MASK_VECTOR_SIZE {
				break
			}
		}
	}
	d.maskVector.SetBits(vectorBits...)
	d.maskMinBit = vectorBits[0]
	d.maskMaxBit = vectorBits[MASK_VECTOR_SIZE-1]
}

func (d *Ddbs) generateVectorTable(acls []*Acl) {
	for _, acl := range acls {
		for _, match := range acl.AllMatcheds {
			index := match.GetTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit)
			d.table[index] = append(d.table[index], TableItem{match, acl.MatchedMask, acl.Action, acl.NpbActions, acl.Id})
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
	d.generateInterestKeys(endpointData, packet, false)
	packet.GenerateMatchedField()
	srcEpc := endpointData.SrcInfo.GetEpc()
	dstEpc := endpointData.DstInfo.GetEpc()

	portForwardPolicy, portBackwardPolicy, vlanPolicy, findPolicy := INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA

	// forward正方向
	for _, key := range packet.ForwardMatched {
		index := key.GetTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit)
		for _, item := range d.table[index] {
			if result := key.And(&item.mask); result.Equal(&item.match) {
				if portForwardPolicy == INVALID_POLICY_DATA {
					portForwardPolicy = new(PolicyData)
				}
				portForwardPolicy.Merge(item.aclAction, item.npbActions, item.aclID, FORWARD)
				if item.match.Get(MATCHED_VLAN) > 0 {
					if vlanPolicy == INVALID_POLICY_DATA {
						vlanPolicy = new(PolicyData)
					}
					vlanPolicy.Merge(item.aclAction, item.npbActions, item.aclID, FORWARD)
				}
			}
		}
	}

	// backward正方向
	for _, key := range packet.BackwardMatched {
		index := key.GetTableIndex(&d.maskVector, d.maskMinBit, d.maskMaxBit)
		for _, item := range d.table[index] {
			if result := key.And(&item.mask); result.Equal(&item.match) {
				if portBackwardPolicy == INVALID_POLICY_DATA {
					portBackwardPolicy = new(PolicyData)
				}
				portBackwardPolicy.Merge(item.aclAction, item.npbActions, item.aclID, BACKWARD)
				if item.match.Get(MATCHED_VLAN) > 0 {
					if vlanPolicy == INVALID_POLICY_DATA {
						vlanPolicy = new(PolicyData)
					}
					vlanPolicy.Merge(item.aclAction, item.npbActions, item.aclID, FORWARD)
				}
			}
		}
	}

	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)
	d.cloudPlatformLabeler.RemoveAnonymousGroupIds(endpointStore, packet)
	packetEndpointData := d.cloudPlatformLabeler.UpdateEndpointData(endpointStore, packet)
	mapsForward, mapsBackward := d.addPortFastPolicy(endpointStore, packetEndpointData, srcEpc, dstEpc, packet, portForwardPolicy, portBackwardPolicy)

	if packet.Vlan > 0 {
		d.addVlanFastPolicy(srcEpc, dstEpc, packet, vlanPolicy, endpointData, mapsForward, mapsBackward)
	}

	id := getAclId(vlanPolicy.ACLID, portForwardPolicy.ACLID, portBackwardPolicy.ACLID)
	if id > 0 {
		findPolicy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			length := len(portForwardPolicy.AclActions) + len(portBackwardPolicy.AclActions) + len(vlanPolicy.AclActions)
			findPolicy.AclActions = make([]AclAction, 0, length)
			findPolicy.MergeAclAction(append(vlanPolicy.AclActions, append(portForwardPolicy.AclActions, portBackwardPolicy.AclActions...)...), id)
			findPolicy.AddAclGidBitmaps(packet, false, d.AclGidMap.SrcGroupAclGidMaps[packet.Tap], d.AclGidMap.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			length := len(portForwardPolicy.NpbActions) + len(portBackwardPolicy.NpbActions)
			findPolicy.NpbActions = make([]NpbAction, 0, length)
			findPolicy.MergeNpbAction(append(portForwardPolicy.NpbActions, portBackwardPolicy.NpbActions...), id)
			findPolicy.FormatNpbAction()
			findPolicy.NpbActions = findPolicy.CheckNpbAction(packet, packetEndpointData)
		}
	} else {
		atomic.AddUint64(&d.UnmatchedPacketCount, 1)
	}

	atomic.AddUint64(&d.FirstPathHit, 1)
	atomic.AddUint64(&d.FirstPathHitTick, 1)
	aclHitMax := atomic.LoadUint32(&d.AclHitMax)
	if aclHit := uint32(len(findPolicy.AclActions) + len(findPolicy.NpbActions)); aclHitMax < aclHit {
		atomic.CompareAndSwapUint32(&d.AclHitMax, aclHitMax, aclHit)
	}
	return endpointStore, findPolicy
}

func (d *Ddbs) UpdateAcls(acls []*Acl) {
	// 生成策略InterestMap,更新策略
	d.GenerateInterestMaps(acls)
	d.GenerateGroupAclGidMaps(acls)
	// 生成Ddbs查询表
	d.generateDdbsTable(acls)
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
