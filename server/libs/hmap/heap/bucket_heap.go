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

package heap

import (
	"fmt"
)

const (
	MAX_BUCKET_COUNT    = 100000 // 最大的桶数量限制，防止过量扩展桶
	MAX_FREE_NODE_COUNT = 16     // 最大缓存的pop个数，也是支持同时读的线程数
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

	minBucket         int     // bucketHead中最小非空的桶
	nodeCount         int32   // nodes中节点的数量
	freeNodeIndexList []int32 // Pop之后可重用的Node, 最大不超过MAX_FREE_NODE_COUNT
}

// 向bucketIndex所在的桶插入一个元素x
func (s *BucketHeap) Push(bucketIndex int, x interface{}) error {
	if bucketIndex < 0 || bucketIndex >= MAX_BUCKET_COUNT {
		return fmt.Errorf("bucketIndex %d 溢出，上限为 %d", bucketIndex, MAX_BUCKET_COUNT)
	}
	// 自动扩展bucket数量
	for bucketIndex >= len(s.bucketHead) {
		s.bucketHead = append(s.bucketHead, -1)
	}

	if bucketIndex < s.minBucket {
		s.minBucket = bucketIndex
	}

	// 使用freeNodeIndex存储x
	if len(s.freeNodeIndexList) > 0 {
		freeNodeIndex := s.freeNodeIndexList[len(s.freeNodeIndexList)-1]
		node := &s.nodes[freeNodeIndex]
		node.value = x
		node.next = s.bucketHead[bucketIndex]
		s.bucketHead[bucketIndex] = freeNodeIndex
		s.freeNodeIndexList = s.freeNodeIndexList[:len(s.freeNodeIndexList)-1]
		return nil
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
	return nil
}

// 返回最小bucket中的一个元素，若没有返回nil
// 注意：Pop最多会产生MAX_FREE_NODE_COUNT个未被删除的Node，须及时Push，否则连续的MAX_FREE_NODE_COUNT+1次Pop会导致这个Node被泄漏
func (s *BucketHeap) Pop() interface{} {
	for i := s.minBucket; i < len(s.bucketHead); i++ {
		if s.bucketHead[i] == -1 {
			s.minBucket++
			continue
		}

		// 获取到链表头部并从bucketHead链表中删除
		if len(s.freeNodeIndexList) < MAX_FREE_NODE_COUNT {
			s.freeNodeIndexList = append(s.freeNodeIndexList, s.bucketHead[i])
		}
		node := &s.nodes[s.bucketHead[i]]
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
		nodes:             make([]bucketHeapNode, capacity),
		bucketHead:        make([]int32, buckets),
		freeNodeIndexList: make([]int32, 0, MAX_FREE_NODE_COUNT),
	}

	for i := 0; i < buckets; i++ {
		s.bucketHead[i] = -1
	}

	return s
}
