package segmenttree

import (
	"sync"

	"github.com/golang-collections/go-datastructures/bitarray"
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
	return &SegmentTree{trees, values}, nil
}
