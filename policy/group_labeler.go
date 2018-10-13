package policy

import (
	"github.com/hashicorp/golang-lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	tree "gitlab.x.lan/yunshan/droplet-libs/segmenttree"
)

const (
	GROUP_TREE_DIMENSION = 2
	MAX_LRU_SIZE         = 1000
)

type IpGroupData struct {
	Id    uint32
	EpcId int32
	Type  uint8
	Ips   []string
}

// IpResourceGroup is the labeler for resource groups
type IpResourceGroup struct {
	ipTree CachedIpTree
}

type CachedIpTree CachedTree

func NewIpResourceGroup() *IpResourceGroup {
	ipTree, _ := tree.New(GROUP_TREE_DIMENSION)
	return &IpResourceGroup{CachedIpTree(makeCachedTree(ipTree))}
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

// Update triggers the creation of trees in labeler
func (g *IpResourceGroup) Update(groups []*IpGroupData) {
	ipEntries := make([]tree.Entry, 0, len(groups))
	for _, g := range groups {
		ipEntries = append(ipEntries, ipGroupToEntries(g)...)
	}
	ipTree, err := tree.New(GROUP_TREE_DIMENSION, ipEntries...)
	if err != nil {
		log.Warning("IP resource group error:", err)
	}
	g.ipTree = CachedIpTree(makeCachedTree(ipTree))
}

// Populate fills tags in flow message
func (g *IpResourceGroup) Populate(ip uint32, endpointInfo *EndpointInfo) bool {
	queryResult := g.ipTree.cachedQuery(endpointInfo.L3EpcId, ip)
	ok := queryResult != nil
	for _, v := range queryResult {
		endpointInfo.GroupIds = append(endpointInfo.GroupIds, uint32(v)+IP_GROUP_ID_FLAG)
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
