/**
 * Copyright (c) 2024 Yunshan Networks
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

package idmng

import (
	"fmt"
	"sort"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/server/controller/recorder/common"
)

type inUseIDsProvider interface {
	load() (mapset.Set[int], error) // load ids in use from db
	check([]int) ([]int, error)     // check whether the specified ids are in use
}

type allocator struct {
	org          *common.ORG
	resourceType string

	min       int
	max       int
	usableIDs []int

	inUseIDsProvider inUseIDsProvider
	sorter           sorter

	unusedIDFirst         bool // whether to allocate unused ids first, default is true
	allocationCountStrict bool // whether to strictly allocate the specified number of ids, default is false
}

func newIDAllocator(org *common.ORG, resourceType string, min, max int) allocator {
	return allocator{
		org:           org,
		resourceType:  resourceType,
		min:           min,
		max:           max,
		usableIDs:     make([]int, 0, max-min+1),
		unusedIDFirst: true,
	}
}

func (a *allocator) SetInUseIDsProvider(provider inUseIDsProvider) {
	a.inUseIDsProvider = provider
}

func (a *allocator) SetSorter(sorter sorter) {
	a.sorter = sorter
}

func (a *allocator) SetUnusedIDFirst(unusedIDFirst bool) {
	a.unusedIDFirst = unusedIDFirst
}

func (a *allocator) SetAllocationCountStrict(allocationCountStrict bool) {
	a.allocationCountStrict = allocationCountStrict
}

func (a *allocator) Refresh() error {
	log.Infof("refresh %s ids pool started", a.resourceType, a.org.LogPrefix)
	inUseIDSet, err := a.inUseIDsProvider.load()
	if err != nil {
		return err
	}
	a.usableIDs = a.generateSortedUsableIDs(a.generateAllIDSet(), inUseIDSet)
	log.Infof("refresh %s ids pool (usable ids count: %d) completed", a.resourceType, len(a.usableIDs), a.org.LogPrefix)
	return nil
}

func (a *allocator) generateAllIDSet() mapset.Set[int] {
	allIDSet := mapset.NewSet[int]()
	for i := a.min; i <= a.max; i++ {
		allIDSet.Add(i)
	}
	return allIDSet
}

func (a *allocator) generateSortedUsableIDs(allIDSet, inUseIDSet mapset.Set[int]) []int {
	var usableIDs []int
	if inUseIDSet.Cardinality() == 0 {
		usableIDs = a.sorter.sortSet(allIDSet)
	} else {
		// usable ids = all ids [min, max] - ids in use in db
		// 可用 id = 所有 id [min, max] - db 中正在使用的 id
		usableIDSet := allIDSet.Difference(inUseIDSet)
		usableIDs = a.sorter.sortSet(usableIDSet)

		if a.unusedIDFirst {
			// usable ids that have been used and recycled after use
			// 可用 id 中被分配使用后已归还的 id
			usedIDSet := a.sorter.generateUsedIDSet(usableIDs, inUseIDSet)
			usedIDs := a.sorter.sortSet(usedIDSet)

			// usable ids that have not been used
			// 可用 id 中未被使用过的 id
			unusedIDs := a.sorter.sortSet(usableIDSet.Difference(usedIDSet))

			// id pool allocation order: ids that have not been used first, ids that have been recycled after use
			// id 池分配顺序：未被使用过的 id 优先，被使用过后已归还的 id 在后
			usableIDs = append(unusedIDs, usedIDs...)
		}
	}
	return usableIDs
}

func (a *allocator) Allocate(count int) ([]int, error) {
	if len(a.usableIDs) == 0 {
		log.Errorf("%s has no more usable ids, usable ids count: 0", a.resourceType, a.org.LogPrefix)
		return nil, fmt.Errorf("%s has no more usable ids, usable ids count: 0", a.resourceType)
	}

	trueCount := count
	if len(a.usableIDs) < count {
		if a.allocationCountStrict {
			log.Errorf("%s has no more usable ids, usable ids count: %d, except ids count: %d", a.resourceType, len(a.usableIDs), count, a.org.LogPrefix)
			return nil, fmt.Errorf("%s has no more usable ids, usable ids count: %d, except ids count: %d", a.resourceType, len(a.usableIDs), count)
		}
		trueCount = len(a.usableIDs)
	}

	ids := make([]int, trueCount)
	copy(ids, a.usableIDs[:trueCount])

	inUseIDs, err := a.inUseIDsProvider.check(ids)
	if err != nil {
		return ids, err
	}
	if len(inUseIDs) != 0 {
		if a.allocationCountStrict {
			log.Errorf("%s ids: %v are in use", a.resourceType, inUseIDs, a.org.LogPrefix)
			return nil, fmt.Errorf("%s ids: %v are in use", a.resourceType, inUseIDs)
		}
		ids = mapset.NewSet(ids...).Difference(mapset.NewSet(inUseIDs...)).ToSlice()
	}

	log.Infof("allocated %s ids: %v (expected count: %d, true count: %d)", a.resourceType, ids, trueCount, len(ids), a.org.LogPrefix)
	a.usableIDs = a.usableIDs[trueCount:]
	return ids, nil
}

func (a *allocator) Recycle(ids []int) {
	a.sorter.sort(ids)
	a.usableIDs = append(a.usableIDs, ids...)
	log.Infof("recycled %s ids: %v", a.resourceType, ids, a.org.LogPrefix)
}

type sorter interface {
	sort([]int)
	sortSet(mapset.Set[int]) []int
	generateUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int]
}

type AscIDAllocator struct {
	allocator
}

func NewAscIDAllocator(org *common.ORG, resourceType string, min, max int) AscIDAllocator {
	a := AscIDAllocator{
		allocator: newIDAllocator(org, resourceType, min, max),
	}
	a.SetSorter(&a)
	return a
}

func (a *AscIDAllocator) generateUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int] {
	maxInUseID := a.sortSet(inUseIDSet)[inUseIDSet.Cardinality()-1]
	usedIDSet := mapset.NewSet[int]()
	for _, id := range sortedUsableIDs {
		if id < maxInUseID {
			usedIDSet.Add(id)
		} else {
			break
		}
	}
	return usedIDSet
}

// sortSet sorts ints set in ascending order
func (a *AscIDAllocator) sortSet(ints mapset.Set[int]) []int {
	s := ints.ToSlice()
	a.sort(s)
	return s
}

// sort sorts ints slice in ascending order
func (a *AscIDAllocator) sort(ints []int) {
	sort.Ints(ints)
}

type descIDAllocator struct {
	allocator
}

func NewDescIDAllocator(org *common.ORG, resourceType string, min, max int) descIDAllocator {
	a := descIDAllocator{
		allocator: newIDAllocator(org, resourceType, min, max),
	}
	a.SetSorter(&a)
	return a
}

func (a *descIDAllocator) generateUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int] {
	minInUseID := a.sortSet(inUseIDSet)[inUseIDSet.Cardinality()-1]
	usedIDSet := mapset.NewSet[int]()
	for _, id := range sortedUsableIDs {
		if id > minInUseID {
			usedIDSet.Add(id)
		} else {
			break
		}
	}
	return usedIDSet
}

// sortSet sorts ints set in descending order
func (a *descIDAllocator) sortSet(ints mapset.Set[int]) []int {
	s := ints.ToSlice()
	a.sort(s)
	return s
}

// sort sorts ints slice in descending order
func (a *descIDAllocator) sort(ints []int) {
	sort.Ints(ints)
	sort.Sort(sort.Reverse(sort.IntSlice(ints)))
}
