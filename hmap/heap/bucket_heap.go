package heap

import (
	"fmt"
)

type bucketHeapNode struct {
	value interface{}
	next  int32 // 值为 nodes[i] 所在链表的下一个节点的 nodes 下标
}

// 注意：不是线程安全的
// 一个高效的特殊小顶堆实现，结合桶排序的思路，针对节点的SortKey值域小且重复多的场景。
// 堆中的节点是一个 <bucketIndex int, x interface{}> 的二元组，
// bucketIndex用于决定 x 在 Heap 中的位置（SortKey）。
type BucketHeap struct {
	nodes      []bucketHeapNode // 长度为待排序的最大节点数量
	bucketHead []int32          // 长度为桶的个数，定长

	minBucket     int   // bucketHead中最小非空的桶
	nodeCount     int32 // nodes中节点的数量
	freeNodeIndex int32 // 最近一次Pop之后可用的Node
}

// 向bucketIndex所在的桶插入一个元素x
func (s *BucketHeap) Push(bucketIndex int, x interface{}) {
	if bucketIndex < 0 || bucketIndex >= len(s.bucketHead) {
		panic(fmt.Sprintf("bucketIndex %d 溢出，上限为 %d", bucketIndex, len(s.bucketHead)-1))
	}
	if bucketIndex < s.minBucket {
		s.minBucket = bucketIndex
	}

	// 使用freeNodeIndex存储x
	if s.freeNodeIndex != -1 {
		node := &s.nodes[s.freeNodeIndex]
		node.value = x
		node.next = s.bucketHead[bucketIndex]
		s.bucketHead[bucketIndex] = s.freeNodeIndex
		s.freeNodeIndex = -1
		return
	}

	// 使用新的Node存储x
	if s.nodeCount >= int32(len(s.nodes)) {
		panic(fmt.Sprintf("nodes缓冲区溢出，当前长度已达到上限 %d", s.nodeCount))
	}
	node := &s.nodes[s.nodeCount]
	node.value = x
	node.next = s.bucketHead[bucketIndex]
	s.bucketHead[bucketIndex] = s.nodeCount
	s.nodeCount++
}

// 返回最小bucket中的一个元素，若没有返回nil
// 注意：Pop可能会产生一个未被删除的Node，必须及时Push，否则下一次Pop会导致这个Node被泄漏
func (s *BucketHeap) Pop() interface{} {
	for i := s.minBucket; i < len(s.bucketHead); i++ {
		if s.bucketHead[i] == -1 {
			s.minBucket++
			continue
		}

		// 获取到链表头部并从bucketHead链表中删除
		s.freeNodeIndex = s.bucketHead[i]
		node := &s.nodes[s.freeNodeIndex]
		s.bucketHead[i] = node.next

		// 将node清空
		x := node.value
		node.value = nil
		node.next = -1

		return x
	}
	return nil
}

// buckets：桶的数量，桶是编号从0开始的连续自然数
// capacity：在sorter中驻留的最大节点数量，若已满Push会报错
func NewBucketHeap(buckets, capacity int) *BucketHeap {
	s := &BucketHeap{
		nodes:         make([]bucketHeapNode, capacity),
		bucketHead:    make([]int32, buckets),
		freeNodeIndex: -1,
	}

	for i := 0; i < buckets; i++ {
		s.bucketHead[i] = -1
	}

	return s
}
