/**
 * 这是线段树的内部类，用于实现单维线段树
 */
package segmenttree

import (
	"sort"

	"github.com/golang-collections/go-datastructures/bitarray"

	list "gitlab.x.lan/yunshan/droplet-libs/linkedlist"
)

type EndpointType = int

const (
	OPEN         EndpointType = iota // ...) endpoint (...
	LEFT_CLOSED                      // ...) [endpoint ...
	RIGHT_CLOSED                     // ... endpoint] (...
)

type TypedEndpoint struct {
	endpoint     Endpoint
	endpointType EndpointType
}

type SortableEndpoints struct {
	sortedEndpoints []TypedEndpoint
}

func (s *SortableEndpoints) Len() int {
	return len(s.sortedEndpoints)
}

func (s *SortableEndpoints) Less(i, j int) bool {
	return s.sortedEndpoints[i].endpoint < s.sortedEndpoints[j].endpoint
}

func (s *SortableEndpoints) Swap(i, j int) {
	s.sortedEndpoints[i], s.sortedEndpoints[j] = s.sortedEndpoints[j], s.sortedEndpoints[i]
}

type SubTree struct {
	interval    IntegerRange
	indexBitSet bitarray.BitArray
	left        *SubTree
	right       *SubTree
}

func (t *SubTree) isLeaf() bool {
	return t.left == nil && t.right == nil
}

type ImmutableSegmentTree struct {
	root *SubTree
}

// 只是构造树，并不包含插入数据
func (t *ImmutableSegmentTree) buildTree(sortedEndpoints []TypedEndpoint) {
	endpointIndexMap := make(map[int64]int)
	for i, typedEndpoint := range sortedEndpoints {
		endpointIndexMap[typedEndpoint.endpoint] = i
	}
	queue := list.New()
	queue.PushBack(t.root)
	for value := queue.PopFront(); value != nil; value = queue.PopFront() {
		subtree := value.(*SubTree)
		interval := subtree.interval
		lowerIndex := -1
		if interval.hasLowerBound() {
			lowerIndex = endpointIndexMap[interval.lowerEndpoint()]
		}
		var upperIndex int
		if interval.hasUpperBound() {
			upperIndex = endpointIndexMap[interval.upperEndpoint()]
		} else {
			upperIndex = len(sortedEndpoints)
		}
		if upperIndex-lowerIndex <= 1 {
			continue
		}
		middle := sortedEndpoints[(lowerIndex+upperIndex)/2]
		upperClosed := middle.endpointType == LEFT_CLOSED
		if lowerIndex == -1 {
			subtree.left = &SubTree{interval: upToRange(middle.endpoint, upperClosed)}
		} else {
			lower := sortedEndpoints[lowerIndex]
			lowerClosed := lower.endpointType == RIGHT_CLOSED
			subtree.left = &SubTree{interval: ranged(lower.endpoint, lowerClosed, middle.endpoint, upperClosed)}
		}

		lowerClosed := middle.endpointType == RIGHT_CLOSED
		if upperIndex == len(sortedEndpoints) {
			subtree.right = &SubTree{interval: downToRange(middle.endpoint, lowerClosed)}
		} else {
			upper := sortedEndpoints[upperIndex]
			upperClosed := upper.endpointType == LEFT_CLOSED
			subtree.right = &SubTree{interval: ranged(middle.endpoint, lowerClosed, upper.endpoint, upperClosed)}
		}
		queue.PushBack(subtree.left)
		queue.PushBack(subtree.right)
	}
}

func bitArrayOf(value uint) bitarray.BitArray {
	bits := bitarray.NewSparseBitArray()
	bits.SetBit(uint64(value))
	return bits
}

func (t *ImmutableSegmentTree) insertIndex(interval IntegerRange, index uint) {
	queue := list.New()
	queue.PushBack(t.root)
	for value := queue.PopFront(); value != nil; value = queue.PopFront() {
		subtree := value.(*SubTree)
		curInterval := &subtree.interval
		if !interval.isConnected(curInterval) {
			continue
		} else if interval.encloses(curInterval) { // 子树interval范围被interval完全包含，直接添加
			if subtree.indexBitSet == nil {
				subtree.indexBitSet = bitarray.NewSparseBitArray()
			}
			subtree.indexBitSet.SetBit(uint64(index))
		} else if subtree.isLeaf() { // 子树interval和interval部分重合但没有更多的子树，因此需要拆分interval再次构造左右子树
			intersection := interval.intersection(curInterval)
			if intersection.isEmpty() {
				continue
			}
			if curInterval.hasLowerBound() && curInterval.lowerEndpoint() == intersection.lowerEndpoint() {
				subtree.left = &SubTree{interval: intersection, indexBitSet: bitArrayOf(index)}
				var upperInterval IntegerRange
				if curInterval.hasUpperBound() {
					upperInterval = IntegerRange{Cut{intersection.upperEndpoint(), false}, curInterval.upper}
				} else {
					upperInterval = downToRange(intersection.upperEndpoint(), false)
				}
				subtree.right = &SubTree{interval: upperInterval}
			} else {
				var lowerInterval IntegerRange
				if curInterval.hasLowerBound() {
					lowerInterval = IntegerRange{curInterval.lower, Cut{intersection.lowerEndpoint(), false}}
				} else {
					lowerInterval = upToRange(intersection.lowerEndpoint(), false)
				}
				subtree.left = &SubTree{interval: lowerInterval}
				subtree.right = &SubTree{interval: intersection, indexBitSet: bitArrayOf(index)}
			}
		} else { // 子树interval在interval部分重合且有更多的子树，继续遍历
			if subtree.left != nil {
				queue.PushBack(subtree.left)
			}
			if subtree.right != nil {
				queue.PushBack(subtree.right)
			}
		}
	}
}

func toEndpoints(intervals []IntegerRange) []TypedEndpoint {
	endpointTypeMap := make(map[int64]EndpointType)
	for _, interval := range intervals {
		if interval.hasLowerBound() {
			lower := interval.lowerEndpoint()
			if _, found := endpointTypeMap[lower]; !found {
				if interval.lowerClosed() {
					endpointTypeMap[lower] = RIGHT_CLOSED
				} else {
					endpointTypeMap[lower] = OPEN
				}
			}
		}
		if interval.hasUpperBound() {
			upper := interval.upperEndpoint()
			if interval.upperClosed() {
				endpointTypeMap[upper] = LEFT_CLOSED
			} else {
				endpointTypeMap[upper] = RIGHT_CLOSED
			}
		}
	}

	endpoints := make([]TypedEndpoint, 0, len(endpointTypeMap))
	for key, value := range endpointTypeMap {
		endpoints = append(endpoints, TypedEndpoint{key, value})
	}
	sort.Sort(&SortableEndpoints{endpoints})
	return endpoints
}

func (t *ImmutableSegmentTree) init(intervals []IntegerRange) {
	if len(intervals) <= 0 {
		return
	}

	t.root = &SubTree{interval: RANGE_ALL}
	if len(intervals) > 0 {
		t.buildTree(toEndpoints(intervals))
	}
	for i, interval := range intervals {
		t.insertIndex(interval, uint(i))
	}
}

func (t *ImmutableSegmentTree) query(interval IntegerRange) bitarray.BitArray {
	if !t.root.interval.isConnected(&interval) {
		return bitarray.NewSparseBitArray()
	}
	indexBitSet := bitarray.NewSparseBitArray()
	queue := list.New()
	queue.PushBack(t.root)
	for value := queue.PopFront(); value != nil; value = queue.PopFront() {
		subtree := value.(*SubTree)
		if subtree.indexBitSet != nil {
			indexBitSet = indexBitSet.Or(subtree.indexBitSet)
		}
		if subtree.left != nil && interval.isConnected(&subtree.left.interval) {
			queue.PushBack(subtree.left)
		}
		if subtree.right != nil && interval.isConnected(&subtree.right.interval) {
			queue.PushBack(subtree.right)
		}
	}
	return indexBitSet
}
