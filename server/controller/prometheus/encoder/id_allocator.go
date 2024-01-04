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

package encoder

import (
	"errors"
	"fmt"
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
)

type sorter interface {
	sort([]int)
	sortSet(mapset.Set[int]) []int
	getUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int]
}

type rawDataProvider interface {
	load() (mapset.Set[int], error)
	check([]int) ([]int, error)
}

type idAllocator struct {
	resourceType    string
	min             int
	max             int
	usableIDs       []int
	rawDataProvider rawDataProvider
	sorter          sorter
}

func newIDAllocator(resourceType string, min, max int) idAllocator {
	return idAllocator{
		resourceType: resourceType,
		min:          min,
		max:          max,
		usableIDs:    make([]int, 0, max-min+1),
	}
}

func (ia *idAllocator) allocate(count int) (ids []int, err error) {
	if len(ia.usableIDs) == 0 {
		return nil, errors.New(fmt.Sprintf("%s has no more usable ids, usable ids count: 0", ia.resourceType))
	}

	if len(ia.usableIDs) < count {
		return nil, errors.New(fmt.Sprintf("%s has no more usable ids, usable ids count: %d, except ids count: %d", ia.resourceType, len(ia.usableIDs), count))
	}

	ids = make([]int, count)
	copy(ids, ia.usableIDs[:count])

	inUseIDs, err := ia.rawDataProvider.check(ids)
	if err != nil {
		return
	}
	if len(inUseIDs) != 0 {
		return nil, errors.New(fmt.Sprintf("%s ids: %v are in use", ia.resourceType, inUseIDs))
	}

	log.Infof("allocate %s ids: %v (expected count: %d, true count: %d)", ia.resourceType, ids, count, len(ids))
	ia.usableIDs = ia.usableIDs[count:]
	return
}

func (p *idAllocator) recycle(ids []int) {
	p.sorter.sort(ids)
	p.usableIDs = append(p.usableIDs, ids...)
	log.Infof("recycle %s ids: %v", p.resourceType, ids)
}

func (ia *idAllocator) refresh() error {
	log.Debugf("refresh %s id pools started", ia.resourceType)
	inUseIDSet, err := ia.rawDataProvider.load()
	if err != nil {
		return err
	}
	ia.usableIDs = ia.getSortedUsableIDs(ia.getAllIDSet(), inUseIDSet)
	log.Debugf("refresh %s id pools (usable ids count: %d) completed", ia.resourceType, len(ia.usableIDs))
	return nil
}

func (ia *idAllocator) getAllIDSet() mapset.Set[int] {
	allIDSet := mapset.NewSet[int]()
	for i := ia.min; i <= ia.max; i++ {
		allIDSet.Add(i)
	}
	return allIDSet
}

func (ia *idAllocator) getSortedUsableIDs(allIDSet, inUseIDSet mapset.Set[int]) []int {
	var usableIDs []int
	if inUseIDSet.Cardinality() == 0 {
		usableIDs = ia.sorter.sortSet(allIDSet)
	} else {
		// usable ids = all ids [min, max] - ids in use in db
		// 可用 id = 所有 id [min, max] - db 中正在使用的 id
		usableIDSet := allIDSet.Difference(inUseIDSet)
		usableIDs = ia.sorter.sortSet(usableIDSet)

		// usable ids that have been used and returned
		// 可用 id 中被使用过后已归还的 id
		usedIDSet := ia.sorter.getUsedIDSet(usableIDs, inUseIDSet)
		usedIDs := ia.sorter.sortSet(usedIDSet)

		// usable ids that have not been used
		// 可用 id 中未被使用过的 id
		unusedIDs := ia.sorter.sortSet(usableIDSet.Difference(usedIDSet))

		// id pool allocation order: ids that have not been used first, ids that have been returned after use
		// id 池分配顺序：未被使用过的 id 优先，被使用过后已归还的 id 在后
		usableIDs = append(unusedIDs, usedIDs...)
	}
	return usableIDs
}

type ascIDAllocator struct {
	idAllocator
}

func newAscIDAllocator(resourceType string, min, max int) ascIDAllocator {
	ia := ascIDAllocator{
		idAllocator: newIDAllocator(resourceType, min, max),
	}
	ia.sorter = &ia
	return ia
}

func (ia *ascIDAllocator) getUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int] {
	maxInUseID := ia.sortSet(inUseIDSet)[inUseIDSet.Cardinality()-1]
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

// sortSet sorts ints in set in ascending order
func (ia *ascIDAllocator) sortSet(ints mapset.Set[int]) []int {
	s := ints.ToSlice()
	ia.sort(s)
	return s
}

// sort sorts ints in set in ascending order
func (ia *ascIDAllocator) sort(ints []int) {
	sort.Ints(ints)
}

type descIDAllocator struct {
	idAllocator
}

func newDescIDAllocator(resourceType string, min, max int) descIDAllocator {
	ia := descIDAllocator{
		idAllocator: newIDAllocator(resourceType, min, max),
	}
	ia.sorter = &ia
	return ia
}

func (ia *descIDAllocator) getUsedIDSet(sortedUsableIDs []int, inUseIDSet mapset.Set[int]) mapset.Set[int] {
	minInUseID := ia.sortSet(inUseIDSet)[inUseIDSet.Cardinality()-1]
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

// sortSet sorts ints in set in descending order
func (ia *descIDAllocator) sortSet(ints mapset.Set[int]) []int {
	s := ints.ToSlice()
	ia.sort(s)
	return s
}

// sort sorts ints in slice in descending order
func (ia *descIDAllocator) sort(ints []int) {
	sort.Ints(ints)
	sort.Sort(sort.Reverse(sort.IntSlice(ints)))
}
