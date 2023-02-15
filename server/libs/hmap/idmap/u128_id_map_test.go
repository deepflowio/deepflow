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

package idmap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/hmap"
)

func TestU128IDMapAddOrGet(t *testing.T) {
	m := NewU128IDMap("test", 1024)

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

	m.Close()
}

func TestU128IDMapSize(t *testing.T) {
	m := NewU128IDMap("test", 1024)

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

	m.Close()
}

func TestU128IDMapGet(t *testing.T) {
	m := NewU128IDMap("test", 1024)

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

	m.Close()
}

func TestU128IDMapClear(t *testing.T) {
	m := NewU128IDMap("test", 4)

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

	m.Close()
}

func BenchmarkU128IDMap(b *testing.B) {
	m := NewU128IDMap("test", 1<<26)

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

	m.Close()
}

func BenchmarkU128IDMapWithSlice(b *testing.B) {
	m := NewU128IDMap("test", 1<<26)
	keys := make([][16]byte, b.N*4)
	for i := uint64(0); i < uint64(b.N); i += 4 {
		binary.BigEndian.PutUint64(keys[i][:], i)
		binary.BigEndian.PutUint64(keys[i][8:], i<<1)
		binary.BigEndian.PutUint64(keys[i+1][:], i<<1)
		binary.BigEndian.PutUint64(keys[i+1][8:], i)
		binary.BigEndian.PutUint64(keys[i+2][:], ^i)
		binary.BigEndian.PutUint64(keys[i+2][8:], ^(i << 1))
		binary.BigEndian.PutUint64(keys[i+3][:], ^(i << 1))
		binary.BigEndian.PutUint64(keys[i+3][8:], ^i)
	}

	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); i += 4 {
		// 构造哈希冲突
		m.AddOrGetWithSlice(keys[i][:], 0, uint32(i<<2), false)
		m.AddOrGetWithSlice(keys[i+1][:], 0, uint32(i<<2), false)
		m.AddOrGetWithSlice(keys[i+2][:], 0, uint32(i<<2), false)
		m.AddOrGetWithSlice(keys[i+3][:], 0, uint32(i<<2), false)
	}
	b.Logf("size=%d, width=%d", m.Size(), m.Width())

	m.Close()
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

func TestU128IDMapCollisionChain(t *testing.T) {
	m := NewU128IDMap("test", 1)
	m.SetCollisionChainDebugThreshold(5)

	for i := 0; i < 10; i++ {
		m.AddOrGet(0, uint64(i), 0, false)
	}
	expected := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if chain := m.GetCollisionChain(); !bytes.Equal(chain, expected) {
		t.Errorf("冲突链获取不正确, 应为%v, 实为%v", hmap.DumpHexBytesGrouped(expected, m.KeySize()), hmap.DumpHexBytesGrouped(chain, m.KeySize()))
	}

	m.Clear()
	m.SetCollisionChainDebugThreshold(10)
	for i := 0; i < 10; i++ {
		m.AddOrGet(0, uint64(i), 0, false)
	}
	if len(m.GetCollisionChain()) > 0 {
		t.Error("冲突链获取不正确")
	}

	m.Close()
}
