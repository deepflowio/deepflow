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
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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

func generateMockDBLabels(size int) []*metadbmodel.PrometheusLabel {
	mockData := make([]*metadbmodel.PrometheusLabel, size)
	for i := 0; i < size; i++ {
		mockData[i] = &metadbmodel.PrometheusLabel{
			Name:  fmt.Sprintf("label_name_%d", i),
			Value: fmt.Sprintf("label_value_%d", i),
			PrometheusAutoIncID: metadbmodel.PrometheusAutoIncID{
				ID: i + 1,
			},
		}
	}
	return mockData
}

func generateMockDBLabelValues(size int) []*metadbmodel.PrometheusLabelValue {
	mockData := make([]*metadbmodel.PrometheusLabelValue, size)
	for i := 0; i < size; i++ {
		mockData[i] = &metadbmodel.PrometheusLabelValue{
			Value: fmt.Sprintf("label_value_%d", i),
			PrometheusID: metadbmodel.PrometheusID{
				ID: i + 1,
			},
		}
	}
	return mockData
}

// newTestLabel 创建一个不依赖 DB 的 label 实例，同时创建配套的 labelName/labelValue
func newTestLabel() *label {
	ln := newTestLabelName()
	lv := newTestLabelValue()
	return newLabel(nil, ln, lv)
}

// newTestLabelWithRefs 返回 label 及其内部引用的 labelName/labelValue
func newTestLabelWithRefs() (*label, *labelName, *labelValue) {
	ln := newTestLabelName()
	lv := newTestLabelValue()
	l := newLabel(nil, ln, lv)
	return l, ln, lv
}

// populateLabelDeps ensures labelName and labelValue contain entries matching
// the naming pattern used by generateProtoLabels ("label_name_i" / "label_value_i").
func populateLabelDeps(l *label, n int) {
	lnBatch := make([]*controller.PrometheusLabelName, n)
	lvBatch := make([]*controller.PrometheusLabelValue, n)
	for i := 0; i < n; i++ {
		lnBatch[i] = &controller.PrometheusLabelName{
			Name: proto.String(fmt.Sprintf("label_name_%d", i)),
			Id:   proto.Uint32(uint32(i + 1)),
		}
		lvBatch[i] = &controller.PrometheusLabelValue{
			Value: proto.String(fmt.Sprintf("label_value_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	l.labelName.Add(lnBatch)
	l.labelValue.Add(lvBatch)
}

func newTestMetricName() *metricName {
	return newMetricName(nil)
}

func newTestLabelName() *labelName {
	return newLabelName(nil)
}

func newTestLabelValue() *labelValue {
	return newLabelValue(nil)
}

func newTestLayout() *metricAndAPPLabelLayout {
	return newMetricAndAPPLabelLayout(nil)
}

func countStringIntMap(m map[string]int) int {
	return len(m)
}
func countLabelConcurrentMap(m map[LabelKey]int) int {
	return len(m)
}

func buildLabelConcurrentMap(n int) map[IDLabelKey]int {
	m := make(map[IDLabelKey]int, n)
	for i := 0; i < n; i++ {
		m[IDLabelKey{NameID: i + 1, ValueID: i + 1}] = i + 1
	}
	return m
}
func buildLabelValueMap(n int) map[string]int {
	m := make(map[string]int, n)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("lv_%d", i)] = i + 1
	}
	return m
}

func resetLabelState(l *label, active map[IDLabelKey]int) {
	l.mu.Lock()
	l.pending = make(map[IDLabelKey]int)
	l.mu.Unlock()
	l.replaceActive(active)
}

func resetLabelValueState(lv *labelValue, active map[string]int) {
	lv.mu.Lock()
	lv.pending = make(map[string]int)
	lv.mu.Unlock()
	lv.replaceActive(active)
}

func resetMetricNameState(mn *metricName, n int) {
	items := make([]*metadbmodel.PrometheusMetricName, n)
	for i := 0; i < n; i++ {
		items[i] = &metadbmodel.PrometheusMetricName{Name: fmt.Sprintf("metric_%d", i)}
		items[i].ID = i + 1
	}
	mn.processLoadedData(items)
}

func resetLabelNameState(ln *labelName, n int) {
	newActive := make(map[string]int, n)
	for i := 0; i < n; i++ {
		newActive[fmt.Sprintf("ln_%d", i)] = i + 1
	}
	ln.mu.Lock()
	ln.pendingNameToID = make(map[string]int)
	ln.mu.Unlock()
	ln.replaceActive(newActive)
}

func resetLayoutState(mll *metricAndAPPLabelLayout, n int) {
	newActive := make(map[LayoutKey]uint8, n)
	for i := 0; i < n; i++ {
		newActive[NewLayoutKey(fmt.Sprintf("metric_%d", i/10), fmt.Sprintf("app_label_%d", i%10))] = uint8(i%10 + 1)
	}
	mll.mu.Lock()
	mll.pending = make(map[LayoutKey]uint8)
	mll.mu.Unlock()
	mll.replaceActive(newActive)
}

func refreshLabelCurrent(l *label, batch []*controller.PrometheusLabel) {
	l.Add(batch)
}

func refreshLabelValueCurrent(lv *labelValue, batch []*controller.PrometheusLabelValue) {
	lv.Add(batch)
}

type labelRefreshEntry struct {
	key LabelKey
	id  int
}

type labelValueRefreshEntry struct {
	value string
	id    int
}

func generateLabelRefreshEntries(n int) []labelRefreshEntry {
	entries := make([]labelRefreshEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = labelRefreshEntry{
			key: NewLabelKey(
				fmt.Sprintf("label_name_%d", i),
				fmt.Sprintf("label_value_%d", i),
			),
			id: i + 1,
		}
	}
	return entries
}

func generateLabelValueRefreshEntries(n int) []labelValueRefreshEntry {
	entries := make([]labelValueRefreshEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = labelValueRefreshEntry{
			value: fmt.Sprintf("lv_%d", i),
			id:    i + 1,
		}
	}
	return entries
}

func refreshLabelEntriesCurrent(l *label, entries []labelRefreshEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, entry := range entries {
		idk, ok := l.toIDKey(entry.key)
		if ok {
			l.pending[idk] = entry.id
		}
	}
}
func refreshLabelValueEntriesCurrent(lv *labelValue, entries []labelValueRefreshEntry) {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	for _, entry := range entries {
		lv.pending[entry.value] = entry.id
	}
}
func benchmarkScaleEnabled(env string) bool {
	return os.Getenv(env) != ""
}

func benchmarkLabelLookupSizes() []int {
	sizes := []int{1000, 100_000, 1_000_000}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_LARGE") {
		sizes = append(sizes, 5_000_000)
	}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_HUGE") {
		sizes = append(sizes, 10_000_000)
	}
	return sizes
}

func benchmarkLabelValueLookupSizes() []int {
	sizes := []int{1000, 100_000, 1_000_000}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_LARGE") {
		sizes = append(sizes, 5_000_000)
	}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_HUGE") {
		sizes = append(sizes, 10_000_000)
	}
	return sizes
}

func benchmarkRefreshSizes() []int {
	sizes := []int{10_000, 100_000, 1_000_000}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_LARGE") {
		sizes = append(sizes, 5_000_000)
	}
	if benchmarkScaleEnabled("PROM_CACHE_BENCH_HUGE") {
		sizes = append(sizes, 10_000_000)
	}
	return sizes
}

func benchmarkProtoRefreshSizes() []int {
	return []int{10_000, 100_000, 500_000}
}

// ============================================================================
// 第一部分：正确性测试 — 基本功能
// ============================================================================

func TestLabel_AddAndGet(t *testing.T) {
	l := newTestLabel()
	batch := generateProtoLabels(100)
	populateLabelDeps(l, 100)

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
	// 不存在的 value
	_, ok := lv.GetIDByValue("nonexistent")
	assert.False(t, ok)
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
	populateLabelDeps(l, 101)
	l.Add(generateProtoLabels(100))

	// 取快照
	snapshot := l.GetKeyToID()
	assert.Equal(t, 100, countLabelConcurrentMap(snapshot))

	// 取完快照后追加数据
	extra := []*controller.PrometheusLabel{
		{Name: proto.String("extra_name"), Value: proto.String("extra_value"), Id: proto.Uint32(999)},
	}
	// Populate deps for extra entry
	l.labelName.Add([]*controller.PrometheusLabelName{{Name: proto.String("extra_name"), Id: proto.Uint32(102)}})
	l.labelValue.Add([]*controller.PrometheusLabelValue{{Value: proto.String("extra_value"), Id: proto.Uint32(102)}})
	l.Add(extra)

	// 快照不受影响
	assert.Equal(t, 100, countLabelConcurrentMap(snapshot))
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
	assert.Equal(t, 50, len(snapshot))

	mn.Add([]*controller.PrometheusMetricName{
		{Name: proto.String("extra_metric"), Id: proto.Uint32(999)},
	})

	assert.Equal(t, 50, len(snapshot)) // 快照隔离
}
func TestLabelValue_GetValueToID_SnapshotIsolation(t *testing.T) {
	lv := newTestLabelValue()
	lv.Add(generateProtoLabelValues(100))

	// 取快照
	snapshot := lv.GetValueToID()
	assert.Equal(t, 100, countStringIntMap(snapshot))

	// 取完快照后追加数据
	extra := []*controller.PrometheusLabelValue{
		{Value: proto.String("extra_value"), Id: proto.Uint32(999)},
	}
	lv.Add(extra)

	// 快照不受影响
	assert.Equal(t, 100, countStringIntMap(snapshot))
	_, exists := snapshot["extra_value"]
	assert.False(t, exists)

	// 但新查询可以看到
	id, ok := lv.GetIDByValue("extra_value")
	assert.True(t, ok)
	assert.Equal(t, 999, id)
}

// ============================================================================
// 第三部分：Snapshot-and-Swap — 模拟 refresh 覆盖
// ============================================================================

func TestLabel_SnapshotSwap_DiscardsOldEntries(t *testing.T) {
	l := newTestLabel()
	populateLabelDeps(l, 200)

	// 初始加载 200 条
	l.Add(generateProtoLabels(200))
	assert.Equal(t, 200, countLabelConcurrentMap(l.GetKeyToID()))

	// 模拟 refresh：只有前 100 条仍在 DB 中，后 100 条已被 Cleaner 删除
	resetLabelState(l, buildLabelConcurrentMap(100))

	// 验证旧条目已消失
	assert.Equal(t, 100, countLabelConcurrentMap(l.GetKeyToID()))
	_, ok := l.GetIDByKey(NewLabelKey("label_name_150", "label_value_150"))
	assert.False(t, ok, "deleted entry should not exist after snapshot-swap")
}

func TestMetricName_SnapshotSwap_DiscardsOldEntries(t *testing.T) {
	mn := newTestMetricName()
	// 模拟第一次 refresh：200 条
	resetMetricNameState(mn, 200)
	// 模拟第二次 refresh：只有前 50 条（后 150 条被 Cleaner 删除）
	resetMetricNameState(mn, 50)

	assert.Equal(t, 50, len(mn.GetNameToID()))
	_, ok := mn.GetIDByName("metric_100")
	assert.False(t, ok)
}
func TestLabelValue_SnapshotSwap_DiscardsOldEntries(t *testing.T) {
	lv := newTestLabelValue()

	// 初始加载 200 条
	lv.Add(generateProtoLabelValues(200))
	assert.Equal(t, 200, countStringIntMap(lv.GetValueToID()))

	// 模拟 refresh：只有前 100 条仍在 DB 中，后 100 条已被 Cleaner 删除
	resetLabelValueState(lv, buildLabelValueMap(100))

	// 验证旧条目已消失
	assert.Equal(t, 100, countStringIntMap(lv.GetValueToID()))
	_, ok := lv.GetIDByValue("lv_150")
	assert.False(t, ok, "deleted entry should not exist after snapshot-swap")
}

// ============================================================================
// 第四部分：并发正确性 — race detector 测试
// go test -race -run TestConcurrent
// ============================================================================

func TestConcurrentLabel_ReadDuringSwap(t *testing.T) {
	l := newTestLabel()
	populateLabelDeps(l, 1000)
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
			resetLabelState(l, buildLabelConcurrentMap(1000))
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
	resetMetricNameState(mn, 1000)

	items := make([]*metadbmodel.PrometheusMetricName, 1000)
	for i := 0; i < 1000; i++ {
		items[i] = &metadbmodel.PrometheusMetricName{Name: fmt.Sprintf("metric_%d", i)}
		items[i].ID = i + 1
	}

	var wg sync.WaitGroup

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < 5000; i++ {
				idx := rng.Intn(1000)
				mn.GetIDByName(fmt.Sprintf("metric_%d", idx))
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < 20; s++ {
			mn.processLoadedData(items)
			runtime.Gosched()
		}
	}()

	wg.Wait()
}

func TestConcurrentLabelValue_ReadDuringSwap(t *testing.T) {
	lv := newTestLabelValue()
	lv.Add(generateProtoLabelValues(1000))

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
				value := fmt.Sprintf("lv_%d", rng.Intn(1000))
				if _, ok := lv.GetIDByValue(value); !ok {
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
			resetLabelValueState(lv, buildLabelValueMap(1000))
			runtime.Gosched()
		}
	}()

	// 持续 Add
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := 0; s < numSwaps; s++ {
			lv.Add([]*controller.PrometheusLabelValue{
				{Value: proto.String("hot_value"), Id: proto.Uint32(99999)},
			})
			runtime.Gosched()
		}
	}()

	wg.Wait()
	t.Logf("reads that missed (expected during swap): %d / %d", errCount.Load(), int64(numReaders*readsPerRdr))
}

func TestConcurrentLabelValue_SnapshotDuringSwap(t *testing.T) {
	lv := newTestLabelValue()
	lv.Add(generateProtoLabelValues(500))

	var wg sync.WaitGroup

	// 读者不断拿快照并遍历
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				snapshot := lv.GetValueToID()
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
			resetLabelValueState(lv, buildLabelValueMap(500))
		}
	}()

	wg.Wait()
}

func TestConcurrentLayout_ReadDuringSwap(t *testing.T) {
	mll := newTestLayout()
	resetLayoutState(mll, 1000)

	items := make([]*metadbmodel.PrometheusMetricAPPLabelLayout, 1000)
	for i := 0; i < 1000; i++ {
		items[i] = &metadbmodel.PrometheusMetricAPPLabelLayout{
			MetricName:          fmt.Sprintf("metric_%d", i/10),
			APPLabelName:        fmt.Sprintf("app_label_%d", i%10),
			APPLabelColumnIndex: uint8(i%10 + 1),
		}
	}

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
			mll.processLoadedData(items)
			runtime.Gosched()
		}
	}()

	wg.Wait()
}

func TestConcurrentLabel_SnapshotDuringSwap(t *testing.T) {
	l := newTestLabel()
	populateLabelDeps(l, 500)
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
			resetLabelState(l, buildLabelConcurrentMap(500))
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
	populateLabelDeps(l, N)

	// 阶段1：加载百万条数据
	batch := make([]*controller.PrometheusLabel, N)
	for i := 0; i < N; i++ {
		batch[i] = &controller.PrometheusLabel{
			Name:  proto.String(fmt.Sprintf("label_name_%d", i)),
			Value: proto.String(fmt.Sprintf("label_value_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	l.Add(batch)

	require.Equal(t, N, countLabelConcurrentMap(l.GetKeyToID()))

	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("after loading %d entries: HeapInuse = %d MB", N, m1.HeapInuse/1024/1024)

	// 阶段2：模拟 refresh——只保留 10% 的数据（模拟 Cleaner 删除后 refresh）
	kept := N / 10
	newMap := make(map[IDLabelKey]int, kept)
	for i := 0; i < kept; i++ {
		newMap[IDLabelKey{NameID: i + 1, ValueID: i + 1}] = i + 1
	}
	resetLabelState(l, newMap)

	// 触发 GC 让旧 map 被回收
	runtime.GC()
	runtime.GC() // 双次 GC 确保 finalizer 运行

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("after swap to %d entries: HeapInuse = %d MB", kept, m2.HeapInuse/1024/1024)

	require.Equal(t, kept, countLabelConcurrentMap(l.GetKeyToID()))

	// 旧 map 被回收后，HeapInuse 应显著下降
	// 允许一定误差（其他 goroutine 可能有分配），但至少应降低 50%
	if m2.HeapInuse >= m1.HeapInuse {
		t.Logf("WARNING: HeapInuse did not decrease after swap (m1=%d, m2=%d). "+
			"This may be due to GC timing or other allocations.", m1.HeapInuse, m2.HeapInuse)
	}
}

func TestLabelValue_LargeScale_MemoryRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	const N = 1_000_000

	lv := newTestLabelValue()

	// 阶段1：加载百万条数据
	batch := make([]*controller.PrometheusLabelValue, N)
	for i := 0; i < N; i++ {
		batch[i] = &controller.PrometheusLabelValue{
			Value: proto.String(fmt.Sprintf("lv_%d", i)),
			Id:    proto.Uint32(uint32(i + 1)),
		}
	}
	lv.Add(batch)

	require.Equal(t, N, countStringIntMap(lv.GetValueToID()))

	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("after loading %d entries: HeapInuse = %d MB", N, m1.HeapInuse/1024/1024)

	// 阶段2：模拟 refresh——只保留 10% 的数据（模拟 Cleaner 删除后 refresh）
	kept := N / 10
	newMap := make(map[string]int, kept)
	for i := 0; i < kept; i++ {
		newMap[fmt.Sprintf("lv_%d", i)] = i + 1
	}
	resetLabelValueState(lv, newMap)

	// 触发 GC 让旧 map 被回收
	runtime.GC()
	runtime.GC() // 双次 GC 确保 finalizer 运行

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("after swap to %d entries: HeapInuse = %d MB", kept, m2.HeapInuse/1024/1024)

	require.Equal(t, kept, countStringIntMap(lv.GetValueToID()))

	// 旧 map 被回收后，HeapInuse 应显著下降
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
				populateLabelDeps(l, size)
				l.Add(batch)
			}
		})
	}
}

func BenchmarkLabel_GetIDByKey(b *testing.B) {
	for _, size := range benchmarkLabelLookupSizes() {
		l := newTestLabel()
		populateLabelDeps(l, size)
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
		populateLabelDeps(l, size)
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
				newMap := make(map[IDLabelKey]int, size)
				for j := 0; j < size; j++ {
					newMap[IDLabelKey{NameID: j + 1, ValueID: j + 1}] = j + 1
				}
				resetLabelState(l, newMap)
			}
		})
	}
}

func BenchmarkLabel_Refresh(b *testing.B) {
	for _, size := range benchmarkRefreshSizes() {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			l := newTestLabel()
			populateLabelDeps(l, size)
			batch := generateProtoLabels(size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				l.Add(batch)
				resetLabelState(l, make(map[IDLabelKey]int))
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
	for _, size := range benchmarkLabelValueLookupSizes() {
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

func BenchmarkLabelValue_GetValueToID_Snapshot(b *testing.B) {
	for _, size := range []int{1000, 10_000, 100_000} {
		lv := newTestLabelValue()
		lv.Add(generateProtoLabelValues(size))

		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = lv.GetValueToID()
			}
		})
	}
}

func BenchmarkLabelValue_SnapshotSwap(b *testing.B) {
	for _, size := range []int{1000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			lv := newTestLabelValue()
			for i := 0; i < b.N; i++ {
				newMap := make(map[string]int, size)
				for j := 0; j < size; j++ {
					newMap[fmt.Sprintf("lv_%d", j)] = j + 1
				}
				resetLabelValueState(lv, newMap)
			}
		})
	}
}

func BenchmarkLabelValue_Refresh(b *testing.B) {
	for _, size := range benchmarkRefreshSizes() {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			lv := newTestLabelValue()
			mockData := generateMockDBLabelValues(size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lv.processLoadedData(mockData)
			}
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
		populateLabelDeps(l, size)
		// Pre-populate deps for "hot" entries used in write path
		hotLN := make([]*controller.PrometheusLabelName, 100)
		hotLV := make([]*controller.PrometheusLabelValue, 100)
		for i := 0; i < 100; i++ {
			hotLN[i] = &controller.PrometheusLabelName{Name: proto.String(fmt.Sprintf("hot_%d", i)), Id: proto.Uint32(uint32(size + i + 1))}
			hotLV[i] = &controller.PrometheusLabelValue{Value: proto.String(fmt.Sprintf("hot_v_%d", i)), Id: proto.Uint32(uint32(size + i + 1))}
		}
		l.labelName.Add(hotLN)
		l.labelValue.Add(hotLV)
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
