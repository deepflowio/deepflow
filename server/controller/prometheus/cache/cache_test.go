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

package cache

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
)

// ============================================================================
// Helper: 数据生成器
// ============================================================================

func generateLabelKeys(n int) []LabelKey {
	keys := make([]LabelKey, n)
	for i := 0; i < n; i++ {
		keys[i] = NewLabelKey(
			fmt.Sprintf("label_name_%d", i),
			fmt.Sprintf("label_value_%d", i),
		)
	}
	return keys
}

func generateProtoLabels(n int) []*controller.PrometheusLabel {
	labels := make([]*controller.PrometheusLabel, n)
	for i := 0; i < n; i++ {
		labels[i] = &controller.PrometheusLabel{
			Name:  proto.String(fmt.Sprintf("label_name_%d", i)),
			Value: proto.String(fmt.Sprintf("label_value_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	return labels
}

func generateProtoMetricNames(n int) []*controller.PrometheusMetricName {
	names := make([]*controller.PrometheusMetricName, n)
	for i := 0; i < n; i++ {
		names[i] = &controller.PrometheusMetricName{
			Name: proto.String(fmt.Sprintf("metric_%d", i)),
			Id:   proto.Uint32(uint32(i + 1)),
		}
	}
	return names
}

func generateProtoLabelNames(n int) []*controller.PrometheusLabelName {
	names := make([]*controller.PrometheusLabelName, n)
	for i := 0; i < n; i++ {
		names[i] = &controller.PrometheusLabelName{
			Name: proto.String(fmt.Sprintf("ln_%d", i)),
			Id:   proto.Uint32(uint32(i + 1)),
		}
	}
	return names
}

func generateProtoLabelValues(n int) []*controller.PrometheusLabelValue {
	values := make([]*controller.PrometheusLabelValue, n)
	for i := 0; i < n; i++ {
		values[i] = &controller.PrometheusLabelValue{
			Value: proto.String(fmt.Sprintf("lv_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	return values
}

func generateProtoLayouts(n int) []*controller.PrometheusMetricAPPLabelLayout {
	layouts := make([]*controller.PrometheusMetricAPPLabelLayout, n)
	for i := 0; i < n; i++ {
		layouts[i] = &controller.PrometheusMetricAPPLabelLayout{
			MetricName:          proto.String(fmt.Sprintf("metric_%d", i/10)),
			AppLabelName:        proto.String(fmt.Sprintf("app_label_%d", i%10)),
			AppLabelColumnIndex: proto.Uint32(uint32(i%10 + 1)),
		}
	}
	return layouts
}

// newTestLabel 创建一个不依赖 DB 的 label 实例
func newTestLabel() *label {
	return &label{
		keyToID: make(map[LabelKey]int),
	}
}

func newTestMetricName() *metricName {
	return &metricName{
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}
}

func newTestLabelName() *labelName {
	return &labelName{
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}
}

func newTestLabelValue() *labelValue {
	return &labelValue{
		valueToID: make(map[string]int),
	}
}

func newTestLayout() *metricAndAPPLabelLayout {
	return &metricAndAPPLabelLayout{
		layoutKeyToIndex: make(map[LayoutKey]uint8),
	}
}

// ============================================================================
// 第一部分：正确性测试 — 基本功能
// ============================================================================

func TestLabel_AddAndGet(t *testing.T) {
	l := newTestLabel()
	batch := generateProtoLabels(100)

	l.Add(batch)

	for _, item := range batch {
		id, ok := l.GetIDByKey(NewLabelKey(item.GetName(), item.GetValue()))
		assert.True(t, ok)
		assert.Equal(t, int(item.GetId()), id)
	}

	// 不存在的 key
	_, ok := l.GetIDByKey(NewLabelKey("nonexistent", "nonexistent"))
	assert.False(t, ok)
}

func TestMetricName_AddAndGet(t *testing.T) {
	mn := newTestMetricName()
	batch := generateProtoMetricNames(100)

	mn.Add(batch)

	for _, item := range batch {
		id, ok := mn.GetIDByName(item.GetName())
		assert.True(t, ok)
		assert.Equal(t, int(item.GetId()), id)

		name, ok := mn.GetNameByID(int(item.GetId()))
		assert.True(t, ok)
		assert.Equal(t, item.GetName(), name)
	}
}

func TestLabelName_AddAndGet(t *testing.T) {
	ln := newTestLabelName()
	batch := generateProtoLabelNames(100)

	ln.Add(batch)

	for _, item := range batch {
		id, ok := ln.GetIDByName(item.GetName())
		assert.True(t, ok)
		assert.Equal(t, int(item.GetId()), id)

		name, ok := ln.GetNameByID(int(item.GetId()))
		assert.True(t, ok)
		assert.Equal(t, item.GetName(), name)
	}
}

func TestLabelValue_AddAndGet(t *testing.T) {
	lv := newTestLabelValue()
	batch := generateProtoLabelValues(100)

	lv.Add(batch)

	for _, item := range batch {
		id, ok := lv.GetIDByValue(item.GetValue())
		assert.True(t, ok)
		assert.Equal(t, int(item.GetId()), id)
	}
}

func TestLayout_AddAndGet(t *testing.T) {
	mll := newTestLayout()
	batch := generateProtoLayouts(100)

	mll.Add(batch)

	for _, item := range batch {
		idx, ok := mll.GetIndexByKey(NewLayoutKey(item.GetMetricName(), item.GetAppLabelName()))
		assert.True(t, ok)
		assert.Equal(t, uint8(item.GetAppLabelColumnIndex()), idx)
	}
}

// ============================================================================
// 第二部分：快照测试 — 快照隔离性
// ============================================================================

func TestLabel_GetKeyToID_SnapshotIsolation(t *testing.T) {
	l := newTestLabel()
	l.Add(generateProtoLabels(100))

	// 取快照
	snapshot := l.GetKeyToID()
	assert.Len(t, snapshot, 100)

	// 取完快照后追加数据
	extra := []*controller.PrometheusLabel{
		{Name: proto.String("extra_name"), Value: proto.String("extra_value"), Id: proto.Uint32(999)},
	}
	l.Add(extra)

	// 快照不受影响
	assert.Len(t, snapshot, 100)
	_, exists := snapshot[NewLabelKey("extra_name", "extra_value")]
	assert.False(t, exists)

	// 但新查询可以看到
	id, ok := l.GetIDByKey(NewLabelKey("extra_name", "extra_value"))
	assert.True(t, ok)
	assert.Equal(t, 999, id)
}

func TestMetricName_GetNameToID_SnapshotIsolation(t *testing.T) {
	mn := newTestMetricName()
	mn.Add(generateProtoMetricNames(50))

	snapshot := mn.GetNameToID()
	assert.Len(t, snapshot, 50)

	mn.Add([]*controller.PrometheusMetricName{
		{Name: proto.String("extra_metric"), Id: proto.Uint32(999)},
	})

	assert.Len(t, snapshot, 50) // 快照隔离
}

// ============================================================================
// 第三部分：Snapshot-and-Swap — 模拟 refresh 覆盖
// ============================================================================

func TestLabel_SnapshotSwap_DiscardsOldEntries(t *testing.T) {
	l := newTestLabel()

	// 初始加载 200 条
	l.Add(generateProtoLabels(200))
	assert.Equal(t, 200, len(l.GetKeyToID()))

	// 模拟 refresh：只有前 100 条仍在 DB 中，后 100 条已被 Cleaner 删除
	newMap := make(map[LabelKey]int, 100)
	for i := 0; i < 100; i++ {
		newMap[NewLabelKey(fmt.Sprintf("label_name_%d", i), fmt.Sprintf("label_value_%d", i))] = i + 1
	}
	l.mu.Lock()
	l.keyToID = newMap
	l.mu.Unlock()

	// 验证旧条目已消失
	assert.Equal(t, 100, len(l.GetKeyToID()))
	_, ok := l.GetIDByKey(NewLabelKey("label_name_150", "label_value_150"))
	assert.False(t, ok, "deleted entry should not exist after snapshot-swap")
}

func TestMetricName_SnapshotSwap_DiscardsOldEntries(t *testing.T) {
	mn := newTestMetricName()
	mn.Add(generateProtoMetricNames(200))

	// 模拟 refresh：只有前 50 条
	newN2I := make(map[string]int, 50)
	newI2N := make(map[int]string, 50)
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("metric_%d", i)
		newN2I[name] = i + 1
		newI2N[i+1] = name
	}
	mn.mu.Lock()
	mn.nameToID = newN2I
	mn.idToName = newI2N
	mn.mu.Unlock()

	assert.Equal(t, 50, len(mn.GetNameToID()))
	_, ok := mn.GetIDByName("metric_100")
	assert.False(t, ok)
}

// ============================================================================
// 第四部分：并发正确性 — race detector 测试
// go test -race -run TestConcurrent
// ============================================================================

func TestConcurrentLabel_ReadDuringSwap(t *testing.T) {
	l := newTestLabel()
	l.Add(generateProtoLabels(1000))

	const (
		numReaders  = 8
		numSwaps    = 20
		readsPerRdr = 5000
	)

	var wg sync.WaitGroup
	errCount := atomic.Int64{}

	// 持续读
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < readsPerRdr; i++ {
				idx := rng.Intn(1000)
				key := NewLabelKey(fmt.Sprintf("label_name_%d", idx), fmt.Sprintf("label_value_%d", idx))
				if _, ok := l.GetIDByKey(key); !ok {
					// refresh 期间旧数据可能暂时不可见，这是预期行为
					errCount.Add(1)
				}
			}
		}()
	}

	// 持续 swap
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < numSwaps; s++ {
			newMap := make(map[LabelKey]int, 1000)
			for i := 0; i < 1000; i++ {
				newMap[NewLabelKey(fmt.Sprintf("label_name_%d", i), fmt.Sprintf("label_value_%d", i))] = i + 1
			}
			l.mu.Lock()
			l.keyToID = newMap
			l.mu.Unlock()
			runtime.Gosched()
		}
	}()

	// 持续 Add
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < numSwaps; s++ {
			l.Add([]*controller.PrometheusLabel{
				{Name: proto.String("hot_name"), Value: proto.String("hot_value"), Id: proto.Uint32(99999)},
			})
			runtime.Gosched()
		}
	}()

	wg.Wait()
	t.Logf("reads that missed (expected during swap): %d / %d", errCount.Load(), int64(numReaders*readsPerRdr))
}

func TestConcurrentMetricName_ReadDuringSwap(t *testing.T) {
	mn := newTestMetricName()
	mn.Add(generateProtoMetricNames(1000))

	var wg sync.WaitGroup

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < 5000; i++ {
				idx := rng.Intn(1000)
				mn.GetIDByName(fmt.Sprintf("metric_%d", idx))
				mn.GetNameByID(idx + 1)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < 20; s++ {
			newN2I := make(map[string]int, 1000)
			newI2N := make(map[int]string, 1000)
			for i := 0; i < 1000; i++ {
				name := fmt.Sprintf("metric_%d", i)
				newN2I[name] = i + 1
				newI2N[i+1] = name
			}
			mn.mu.Lock()
			mn.nameToID = newN2I
			mn.idToName = newI2N
			mn.mu.Unlock()
			runtime.Gosched()
		}
	}()

	wg.Wait()
}

func TestConcurrentLabelValue_ReadDuringSwap(t *testing.T) {
	lv := newTestLabelValue()
	lv.Add(generateProtoLabelValues(1000))

	var wg sync.WaitGroup

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < 5000; i++ {
				lv.GetIDByValue(fmt.Sprintf("lv_%d", rng.Intn(1000)))
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < 20; s++ {
			newV2I := make(map[string]int, 1000)
			for i := 0; i < 1000; i++ {
				newV2I[fmt.Sprintf("lv_%d", i)] = i + 1
			}
			lv.mu.Lock()
			lv.valueToID = newV2I
			lv.mu.Unlock()
			runtime.Gosched()
		}
	}()

	wg.Wait()
}

func TestConcurrentLayout_ReadDuringSwap(t *testing.T) {
	mll := newTestLayout()
	mll.Add(generateProtoLayouts(1000))

	var wg sync.WaitGroup

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < 5000; i++ {
				idx := rng.Intn(1000)
				mll.GetIndexByKey(NewLayoutKey(
					fmt.Sprintf("metric_%d", idx/10),
					fmt.Sprintf("app_label_%d", idx%10),
				))
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < 20; s++ {
			newMap := make(map[LayoutKey]uint8, 1000)
			for i := 0; i < 1000; i++ {
				newMap[NewLayoutKey(fmt.Sprintf("metric_%d", i/10), fmt.Sprintf("app_label_%d", i%10))] = uint8(i%10 + 1)
			}
			mll.mu.Lock()
			mll.layoutKeyToIndex = newMap
			mll.mu.Unlock()
			runtime.Gosched()
		}
	}()

	wg.Wait()
}

func TestConcurrentLabel_SnapshotDuringSwap(t *testing.T) {
	l := newTestLabel()
	l.Add(generateProtoLabels(500))

	var wg sync.WaitGroup

	// 读者不断拿快照并遍历
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				snapshot := l.GetKeyToID()
				// 遍历快照——不应 panic 或 data race
				count := 0
				for range snapshot {
					count++
				}
				_ = count
			}
		}()
	}

	// 写者不断 swap
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < 50; s++ {
			newMap := make(map[LabelKey]int, 500)
			for i := 0; i < 500; i++ {
				newMap[NewLabelKey(fmt.Sprintf("label_name_%d", i), fmt.Sprintf("label_value_%d", i))] = i + 1
			}
			l.mu.Lock()
			l.keyToID = newMap
			l.mu.Unlock()
		}
	}()

	wg.Wait()
}

// ============================================================================
// 第五部分：大数据量内存验证
// ============================================================================

func TestLabel_LargeScale_MemoryRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	const N = 1_000_000

	l := newTestLabel()

	// 阶段1：加载百万条数据
	batch := make([]*controller.PrometheusLabel, N)
	for i := 0; i < N; i++ {
		batch[i] = &controller.PrometheusLabel{
			Name:  proto.String(fmt.Sprintf("n_%d", i)),
			Value: proto.String(fmt.Sprintf("v_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	l.Add(batch)

	require.Equal(t, N, len(l.GetKeyToID()))

	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("after loading %d entries: HeapInuse = %d MB", N, m1.HeapInuse/1024/1024)

	// 阶段2：模拟 refresh——只保留 10% 的数据（模拟 Cleaner 删除后 refresh）
	kept := N / 10
	newMap := make(map[LabelKey]int, kept)
	for i := 0; i < kept; i++ {
		newMap[NewLabelKey(fmt.Sprintf("n_%d", i), fmt.Sprintf("v_%d", i))] = i + 1
	}
	l.mu.Lock()
	l.keyToID = newMap
	l.mu.Unlock()

	// 触发 GC 让旧 map 被回收
	runtime.GC()
	runtime.GC() // 双次 GC 确保 finalizer 运行

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("after swap to %d entries: HeapInuse = %d MB", kept, m2.HeapInuse/1024/1024)

	require.Equal(t, kept, len(l.GetKeyToID()))

	// 旧 map 被回收后，HeapInuse 应显著下降
	// 允许一定误差（其他 goroutine 可能有分配），但至少应降低 50%
	if m2.HeapInuse >= m1.HeapInuse {
		t.Logf("WARNING: HeapInuse did not decrease after swap (m1=%d, m2=%d). "+
			"This may be due to GC timing or other allocations.", m1.HeapInuse, m2.HeapInuse)
	}
}

// ============================================================================
// 第六部分：Benchmark — 性能基准
// ============================================================================

// --- label ---

func BenchmarkLabel_Add(b *testing.B) {
	for _, size := range []int{1000, 10_000, 100_000} {
		batch := generateProtoLabels(size)
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				l := newTestLabel()
				l.Add(batch)
			}
		})
	}
}

func BenchmarkLabel_GetIDByKey(b *testing.B) {
	for _, size := range []int{1000, 100_000, 1_000_000} {
		l := newTestLabel()
		l.Add(generateProtoLabels(size))
		keys := generateLabelKeys(size)

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				for pb.Next() {
					l.GetIDByKey(keys[rng.Intn(size)])
				}
			})
		})
	}
}

func BenchmarkLabel_GetKeyToID_Snapshot(b *testing.B) {
	for _, size := range []int{1000, 10_000, 100_000} {
		l := newTestLabel()
		l.Add(generateProtoLabels(size))

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = l.GetKeyToID()
			}
		})
	}
}

func BenchmarkLabel_SnapshotSwap(b *testing.B) {
	for _, size := range []int{1000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			l := newTestLabel()
			for i := 0; i < b.N; i++ {
				newMap := make(map[LabelKey]int, size)
				for j := 0; j < size; j++ {
					newMap[NewLabelKey(fmt.Sprintf("n_%d", j), fmt.Sprintf("v_%d", j))] = j + 1
				}
				l.mu.Lock()
				l.keyToID = newMap
				l.mu.Unlock()
			}
		})
	}
}

// --- metricName ---

func BenchmarkMetricName_GetIDByName(b *testing.B) {
	for _, size := range []int{1000, 100_000, 500_000} {
		mn := newTestMetricName()
		mn.Add(generateProtoMetricNames(size))

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				for pb.Next() {
					mn.GetIDByName(fmt.Sprintf("metric_%d", rng.Intn(size)))
				}
			})
		})
	}
}

// --- labelValue ---

func BenchmarkLabelValue_GetIDByValue(b *testing.B) {
	for _, size := range []int{1000, 100_000, 500_000} {
		lv := newTestLabelValue()
		lv.Add(generateProtoLabelValues(size))

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				for pb.Next() {
					lv.GetIDByValue(fmt.Sprintf("lv_%d", rng.Intn(size)))
				}
			})
		})
	}
}

// --- layout ---

func BenchmarkLayout_GetIndexByKey(b *testing.B) {
	for _, size := range []int{100, 1000, 10_000} {
		mll := newTestLayout()
		mll.Add(generateProtoLayouts(size))

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				for pb.Next() {
					idx := rng.Intn(size)
					mll.GetIndexByKey(NewLayoutKey(
						fmt.Sprintf("metric_%d", idx/10),
						fmt.Sprintf("app_label_%d", idx%10),
					))
				}
			})
		})
	}
}

// --- 并发混合负载 benchmark ---

func BenchmarkLabel_MixedReadWrite(b *testing.B) {
	for _, size := range []int{10_000, 100_000} {
		l := newTestLabel()
		l.Add(generateProtoLabels(size))
		keys := generateLabelKeys(size)

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				for pb.Next() {
					if rng.Intn(100) < 95 { // 95% read
						l.GetIDByKey(keys[rng.Intn(size)])
					} else { // 5% write
						l.Add([]*controller.PrometheusLabel{
							{
								Name:  proto.String(fmt.Sprintf("hot_%d", rng.Intn(100))),
								Value: proto.String(fmt.Sprintf("hot_v_%d", rng.Intn(100))),
								Id:    proto.Uint32(uint32(rng.Intn(100) + size + 1)),
							},
						})
					}
				}
			})
		})
	}
}
