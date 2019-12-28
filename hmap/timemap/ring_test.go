package timemap

import "testing"

func TestRingIncDecIndex(t *testing.T) {
	r := newRing(1)

	initInc, initDec := 5, 123
	inc, dec := initInc, initDec
	for i := 0; i < _BLOCK_SIZE; i++ {
		inc = r.incIndex(inc)
		if inc < 0 || inc > r.maxIndex {
			t.Fatal("incIndex()实现不正确")
		}
		dec = r.decIndex(dec)
		if dec < 0 || dec > r.maxIndex {
			t.Fatal("decIndex()实现不正确")
		}
	}
	if inc != initInc {
		t.Error("incIndex()实现不正确")
	}
	if dec != initDec {
		t.Error("decIndex()实现不正确")
	}
}

func TestRingGetRemove(t *testing.T) {
	r := newRing(_BLOCK_SIZE)

	lo := 0
	hi := 0
	nodes := make([]int, 10)
	for i := range nodes {
		n := r.pushBack(newTestEntry(0, i+1))
		hi = n.index
		nodes[i] = n.index
	}

	// test remove middle
	if !r.swapRemove(hi / 2) {
		t.Error("应有交换")
	}
	lo++
	if !r.get(hi / 2).entry.Eq(newTestEntry(0, 1)) {
		t.Error("应有交换")
	}
	if r.get(hi/2).index != hi/2 {
		t.Error("index swap处理不正确")
	}

	// test remove head
	if r.swapRemove(lo) {
		t.Error("应没有交换")
	}
	r.swapRemove(hi / 2)
	if !r.get(hi / 2).entry.Eq(newTestEntry(0, 3)) {
		t.Error("swapRemove在第一个索引处理不正确")
	}

	// test recycling blocks
	r = newRing(_BLOCK_SIZE * 2)
	for i := 0; i < _BLOCK_SIZE+1; i++ {
		_ = r.getNext()
	}
	for i := 0; i < _BLOCK_SIZE; i++ {
		r.swapRemove(_BLOCK_SIZE - 1)
	}
	if r.blocks[0] != nil {
		t.Error("block没有回收")
	}
}
