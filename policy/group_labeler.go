package policy

import (
	"github.com/hashicorp/golang-lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	tree "gitlab.x.lan/yunshan/droplet-libs/segmenttree"
)

const (
	GROUP_TREE_DIMENSION = 2
	MAX_LRU_SIZE         = 1000
	VM_GROUP             = 0
	IP_GROUP             = 1
	ANONYMOUS_VM         = 2
	ANONYMOUS_IP         = 3
)

type IpGroupData struct {
	Id    uint32
	EpcId int32
	Type  uint8
	Ips   []string
}

// IpResourceGroup is the labeler for resource groups
type IpResourceGroup struct {
	ipTree       CachedIpTree
	anonymousIds map[uint32]bool
}

type CachedIpTree CachedTree

func NewIpResourceGroup() *IpResourceGroup {
	ipTree, _ := tree.New(GROUP_TREE_DIMENSION)
	return &IpResourceGroup{CachedIpTree(makeCachedTree(ipTree)), make(map[uint32]bool)}
}

func ipGroupToEntries(data *IpGroupData) []tree.Entry {
	entries := make([]tree.Entry, 0, len(data.Ips))
	epcRange := newEpcRange(data.EpcId)
	for _, ip := range data.Ips {
		ipRange, err := newIpRangeFromString(ip)
		if err != nil {
			log.Warningf("Invalid IP %s in resource group %d", ip, data.Id)
			continue
		}
		interval := make([]tree.Interval, GROUP_TREE_DIMENSION)
		interval[0] = epcRange
		interval[1] = ipRange
		entries = append(entries, tree.Entry{Intervals: interval, Value: leafValue(data.Id)})
	}
	return entries
}

func (g *IpResourceGroup) AppendAnonymousId(anonymous map[uint32]bool, group *IpGroupData) {
	if group.Type == ANONYMOUS_IP || group.Type == ANONYMOUS_VM {
		anonymous[group.Id] = true
	}
}

func (g *IpResourceGroup) RemoveAnonymousId(groupIds []uint32) []uint32 {
	result := make([]uint32, 0, len(groupIds))
	for _, v := range groupIds {
		if _, ok := g.anonymousIds[FormatGroupId(v)]; !ok {
			result = append(result, v)
		}
	}

	return result
}

// Update triggers the creation of trees in labeler
func (g *IpResourceGroup) Update(groups []*IpGroupData) {
	ipEntries := make([]tree.Entry, 0, len(groups))
	anonymousIds := make(map[uint32]bool)
	for _, group := range groups {
		ipEntries = append(ipEntries, ipGroupToEntries(group)...)
		g.AppendAnonymousId(anonymousIds, group)
	}
	ipTree, err := tree.New(GROUP_TREE_DIMENSION, ipEntries...)
	if err != nil {
		log.Warning("IP resource group error:", err)
	}
	g.ipTree = CachedIpTree(makeCachedTree(ipTree))
	g.anonymousIds = anonymousIds
}

func generateGroupIds(groupIds []uint32) map[uint32]bool {
	basicGroupIds := map[uint32]bool{}
	for _, id := range groupIds {
		basicGroupIds[id] = true
	}
	return basicGroupIds
}

// Populate fills tags in flow message
func (g *IpResourceGroup) Populate(ip uint32, endpointInfo *EndpointInfo) bool {
	queryResult := g.ipTree.cachedQuery(endpointInfo.L3EpcId, ip)
	ok := queryResult != nil
	basicGroupIds := generateGroupIds(endpointInfo.GroupIds)
	for _, v := range queryResult {
		if _, ok := basicGroupIds[uint32(v)]; !ok {
			endpointInfo.GroupIds = append(endpointInfo.GroupIds, uint32(v)+IP_GROUP_ID_FLAG)
		}
	}

	return ok
}

type CachedTree struct {
	*lru.ARCCache
	tree.Tree
}

func makeCachedTree(t tree.Tree) CachedTree {
	cache, err := lru.NewARC(MAX_LRU_SIZE)
	if err != nil {
		log.Warning("Failed creating cache")
		return CachedTree{nil, t}
	}
	return CachedTree{cache, t}
}

func (t *CachedIpTree) cachedQuery(epc int32, ip uint32) []int32 {
	hasCache := t.ARCCache != nil
	var key uint64
	if hasCache {
		key = (uint64(epc) << 32) | uint64(ip)
		if v, cached := t.ARCCache.Get(key); cached {
			return v.([]int32)
		}
	}
	value := t.Tree.Query(queryEpcRange(epc), newIpRange(ip))
	result := make([]int32, len(value))
	for i := range value {
		result[i] = int32(value[i].(leafValue))
	}
	if hasCache {
		t.ARCCache.Add(key, result)
	}
	return result
}
