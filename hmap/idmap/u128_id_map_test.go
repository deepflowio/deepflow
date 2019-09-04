package idmap

import (
	"testing"
)

func TestU128IDMapAddOrGet(t *testing.T) {
	m := NewU128IDMap(1024)

	exp := true
	if _, ret := m.AddOrGet(0, 1, 1, false); ret != exp {
		t.Errorf("第一次插入，Expected %v found %v", exp, ret)
	}
	exp = false
	if _, ret := m.AddOrGet(0, 1, 2, false); ret != exp {
		t.Errorf("插入同样的值，Expected %v found %v", exp, ret)
	}
	if ret, _ := m.Get(0, 1); ret != 1 {
		t.Errorf("查找失败，Expected %v found %v", 1, ret)
	}
	exp = false
	if _, ret := m.AddOrGet(0, 1, 2, true); ret != exp {
		t.Errorf("插入同样的值，Expected %v found %v", exp, ret)
	}
	if ret, _ := m.Get(0, 1); ret != 2 {
		t.Errorf("查找失败，Expected %v found %v", 2, ret)
	}
	exp = true
	if _, ret := m.AddOrGet(1, 0, 1, false); ret != exp {
		t.Errorf("插入不同的值，Expected %v found %v", exp, ret)
	}

	if m.Size() != 2 {
		t.Errorf("当前长度，Expected %v found %v", 2, m.Size())
	}
}

func TestU128IDMapSize(t *testing.T) {
	m := NewU128IDMap(1024)

	if m.Size() != 0 {
		t.Errorf("当前长度，Expected %v found %v", 0, m.Size())
	}

	m.AddOrGet(0, 1, 1, false)
	if m.Size() != 1 {
		t.Errorf("当前长度，Expected %v found %v", 1, m.Size())
	}
	m.AddOrGet(0, 1, 1, false)
	if m.Size() != 1 {
		t.Errorf("当前长度，Expected %v found %v", 1, m.Size())
	}
	m.AddOrGet(0, 2, 1, false)
	if m.Size() != 2 {
		t.Errorf("当前长度，Expected %v found %v", 2, m.Size())
	}
	m.AddOrGet(1, 0, 1, false)
	if m.Size() != 3 {
		t.Errorf("当前长度，Expected %v found %v", 3, m.Size())
	}
}

func TestU128IDMapGet(t *testing.T) {
	m := NewU128IDMap(1024)

	m.AddOrGet(0, 1, 1, false)
	if _, in := m.Get(0, 1); !in {
		t.Errorf("查找失败")
	}
	if _, in := m.Get(0, 2); in {
		t.Errorf("查找失败")
	}
	if _, in := m.Get(1, 0); in {
		t.Errorf("查找失败")
	}
	m.AddOrGet(1, 0, 1, false)
	if _, in := m.Get(1, 0); !in {
		t.Errorf("查找失败")
	}
}

func TestU128IDMapClear(t *testing.T) {
	m := NewU128IDMap(4)

	m.AddOrGet(0, 1, 1, false)
	m.AddOrGet(0, 1, 1, false)
	m.AddOrGet(0, 2, 1, false)
	m.AddOrGet(1, 0, 1, false)
	m.Clear()
	if m.Size() != 0 {
		t.Errorf("当前长度，Expected %v found %v", 0, m.Size())
	}
	m.AddOrGet(0, 1, 1, false)
	if _, in := m.Get(0, 1); !in {
		t.Errorf("查找失败")
	}
	if m.Size() != 1 {
		t.Errorf("当前长度，Expected %v found %v", 1, m.Size())
	}
}

func BenchmarkU128IDMap(b *testing.B) {
	m := NewU128IDMap(1 << 26)

	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); {
		// 构造哈希冲突
		m.AddOrGet(i, i<<1, uint32(i<<2), false)
		m.AddOrGet(i<<1, i, uint32(i<<2), false)
		m.AddOrGet(^i, ^(i << 1), uint32(i<<2), false)
		m.AddOrGet(^(i << 1), ^i, uint32(i<<2), false)
		i += 4
	}
	b.Logf("size=%d, width=%d", m.Size(), m.Width())
}

type testU128MapKey struct {
	key0 uint64
	key1 uint64
}

func BenchmarkNativeStructMap(b *testing.B) {
	m := make(map[testU128MapKey]uint32)
	key := testU128MapKey{}

	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); {
		key.key0, key.key1 = i, i<<1
		if _, ok := m[key]; !ok {
			m[key] = uint32(i << 2)
		}
		key.key0, key.key1 = i<<1, i
		if _, ok := m[key]; !ok {
			m[key] = uint32(i << 2)
		}
		key.key0, key.key1 = ^i, ^(i << 1)
		if _, ok := m[key]; !ok {
			m[key] = uint32(i << 2)
		}
		key.key0, key.key1 = ^(i << 1), ^i
		if _, ok := m[key]; !ok {
			m[key] = uint32(i << 2)
		}
		i += 4
	}
	b.Logf("size=%d", len(m))
}

func BenchmarkNativeU64Map(b *testing.B) {
	m := make(map[uint64]uint32)

	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); i++ {
		if _, ok := m[i]; !ok {
			m[i] = uint32(i << 2)
		}
	}
	b.Logf("size=%d", len(m))
}
