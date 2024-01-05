/*
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

package segmenttree

import (
	"runtime"
	"sync"

	"github.com/Workiva/go-datastructures/bitarray"
)

func intervalToIntegerRange(interval Interval) IntegerRange {
	lower, lowerClosed := interval.Lower()
	upper, upperClosed := interval.Upper()
	return ranged(lower, lowerClosed, upper, upperClosed)
}

type SegmentTree struct {
	trees  []ImmutableSegmentTree
	values []Value
}

func (t *SegmentTree) Query(intervals ...Interval) []Value {
	dimension := len(t.trees)
	if len(intervals) != dimension || len(t.values) == 0 {
		return nil
	}

	wg := sync.WaitGroup{}
	wg.Add(dimension)
	results := make([]bitarray.BitArray, dimension)
	for d := 0; d < dimension; d++ {
		go func(d int) {
			results[d] = t.trees[d].query(intervalToIntegerRange(intervals[d]))
			wg.Done()
		}(d)
	}
	wg.Wait()
	indexBitSet := results[0]
	for d := 1; d < len(t.trees); d++ {
		indexBitSet = indexBitSet.And(results[d])
	}

	values := make([]Value, 0, len(t.values))
	valueSet := bitarray.NewSparseBitArray()
	for iterator := indexBitSet.Blocks(); iterator.Next(); {
		blockIndex, block := iterator.Value()
		for i := uint64(0); i < 64; i++ {
			if 1<<i&block == 0 {
				continue
			}
			index := blockIndex*64 + i
			value := t.values[index]
			if found, _ := valueSet.GetBit(value.Id()); found {
				continue
			}
			values = append(values, value)
			valueSet.SetBit(value.Id())
		}
	}
	return values
}

func (t *SegmentTree) clear() {
	for i := 0; i < len(t.trees); i++ {
		t.trees[i].clear()
	}
}

func New(dimension int, entries ...Entry) (Tree, error) {
	if dimension == 0 {
		return nil, InvalidDimension
	}

	values := make([]Value, len(entries))
	for i, entry := range entries {
		values[i] = entry.Value
		if len(entry.Intervals) < dimension {
			return nil, InsufficientIntervalLength
		}
	}
	trees := make([]ImmutableSegmentTree, dimension)
	for d := 0; d < dimension; d++ {
		intervals := make([]IntegerRange, len(entries))
		for i, entry := range entries {
			intervals[i] = intervalToIntegerRange(entry.Intervals[d])
		}
		trees[d].init(intervals)
	}
	tree := &SegmentTree{trees: trees, values: values}
	runtime.SetFinalizer(tree, func(t *SegmentTree) {
		t.clear()
	})
	return tree, nil
}
