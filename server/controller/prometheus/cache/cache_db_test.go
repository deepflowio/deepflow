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
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// ============================================================================
// 测试基础设施：SQLite 内存数据库 + ORG 构造
// ============================================================================

const testDBFile = "/tmp/prometheus_cache_test.db"

// setupTestDB 创建 SQLite 数据库并自动建表
func setupTestDB(t testing.TB) *gorm.DB {
	t.Helper()
	os.Remove(testDBFile)
	db, err := gorm.Open(
		sqlite.Open(testDBFile),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 开启 WAL 模式提升写入性能
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA synchronous=OFF")

	// AutoMigrate prometheus 表（layout 需手动建表，因 SQLite 不支持 unsigned）
	err = db.AutoMigrate(
		&metadbmodel.PrometheusMetricName{},
		&metadbmodel.PrometheusLabelName{},
		&metadbmodel.PrometheusLabelValue{},
		&metadbmodel.PrometheusLabel{},
	)
	require.NoError(t, err)

	// SQLite 不支持 "tinyint(3) unsigned"，手动建表
	err = db.Exec(`CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at DATETIME,
		synced_at DATETIME,
		metric_name VARCHAR(256) NOT NULL,
		app_label_name VARCHAR(256) NOT NULL,
		app_label_column_index TINYINT NOT NULL
	)`).Error
	require.NoError(t, err)

	return db
}

func cleanupTestDB(t testing.TB) {
	t.Helper()
	os.Remove(testDBFile)
}

// newTestORG 构造一个使用 SQLite 数据库的 ORG，绕开真实的 metadb.GetDB
func newTestORG(gormDB *gorm.DB) *common.ORG {
	return &common.ORG{
		ID: 1,
		DB: &metadb.DB{DB: gormDB},
	}
}

// batchInsert 通用批量插入，每批 batchSize 条
func batchInsert[T any](db *gorm.DB, items []T, batchSize int) error {
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		if err := db.Create(items[i:end]).Error; err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// 数据生成器（DB 版本 — 带 time 字段，写入真实行）
// ============================================================================

func generateDBMetricNames(n int) []metadbmodel.PrometheusMetricName {
	items := make([]metadbmodel.PrometheusMetricName, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		items[i] = metadbmodel.PrometheusMetricName{
			PrometheusID:           metadbmodel.PrometheusID{ID: i + 1},
			PrometheusOperatedTime: metadbmodel.PrometheusOperatedTime{CreatedAt: now, SyncedAt: now},
			Name:                   fmt.Sprintf("metric_%d", i),
		}
	}
	return items
}

func generateDBLabelNames(n int) []metadbmodel.PrometheusLabelName {
	items := make([]metadbmodel.PrometheusLabelName, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		items[i] = metadbmodel.PrometheusLabelName{
			PrometheusID:           metadbmodel.PrometheusID{ID: i + 1},
			PrometheusOperatedTime: metadbmodel.PrometheusOperatedTime{CreatedAt: now, SyncedAt: now},
			Name:                   fmt.Sprintf("ln_%d", i),
		}
	}
	return items
}

func generateDBLabelValues(n int) []metadbmodel.PrometheusLabelValue {
	items := make([]metadbmodel.PrometheusLabelValue, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		items[i] = metadbmodel.PrometheusLabelValue{
			PrometheusID:           metadbmodel.PrometheusID{ID: i + 1},
			PrometheusOperatedTime: metadbmodel.PrometheusOperatedTime{CreatedAt: now, SyncedAt: now},
			Value:                  fmt.Sprintf("lv_%d", i),
		}
	}
	return items
}

func generateDBLabels(n int) []metadbmodel.PrometheusLabel {
	items := make([]metadbmodel.PrometheusLabel, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		items[i] = metadbmodel.PrometheusLabel{
			PrometheusOperatedTime: metadbmodel.PrometheusOperatedTime{CreatedAt: now, SyncedAt: now},
			Name:                   fmt.Sprintf("n_%d", i),
			Value:                  fmt.Sprintf("v_%d", i),
		}
	}
	return items
}

func generateDBLayouts(n int) []metadbmodel.PrometheusMetricAPPLabelLayout {
	items := make([]metadbmodel.PrometheusMetricAPPLabelLayout, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		items[i] = metadbmodel.PrometheusMetricAPPLabelLayout{
			PrometheusOperatedTime: metadbmodel.PrometheusOperatedTime{CreatedAt: now, SyncedAt: now},
			MetricName:             fmt.Sprintf("metric_%d", i/10),
			APPLabelName:           fmt.Sprintf("app_label_%d", i%10),
			APPLabelColumnIndex:    uint8(i%10 + 1),
		}
	}
	return items
}

// ============================================================================
// Select 精简列正确性测试
// ============================================================================

func TestSelect_MetricName_LoadOnlyIDAndName(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBMetricNames(1000)
	require.NoError(t, batchInsert(db, items, 500))

	mn := &metricName{
		org:      newTestORG(db),
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}

	err := mn.refresh()
	require.NoError(t, err)

	assert.Len(t, mn.GetNameToID(), 1000)
	for i := 0; i < 1000; i++ {
		id, ok := mn.GetIDByName(fmt.Sprintf("metric_%d", i))
		assert.True(t, ok)
		assert.Equal(t, i+1, id)

		name, ok := mn.GetNameByID(i + 1)
		assert.True(t, ok)
		assert.Equal(t, fmt.Sprintf("metric_%d", i), name)
	}
}

func TestSelect_LabelName_LoadOnlyIDAndName(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBLabelNames(1000)
	require.NoError(t, batchInsert(db, items, 500))

	ln := &labelName{
		org:      newTestORG(db),
		nameToID: make(map[string]int),
		idToName: make(map[int]string),
	}

	err := ln.refresh()
	require.NoError(t, err)

	assert.Len(t, ln.GetNameToID(), 1000)
	for i := 0; i < 1000; i++ {
		id, ok := ln.GetIDByName(fmt.Sprintf("ln_%d", i))
		assert.True(t, ok)
		assert.Equal(t, i+1, id)

		name, ok := ln.GetNameByID(i + 1)
		assert.True(t, ok)
		assert.Equal(t, fmt.Sprintf("ln_%d", i), name)
	}
}

func TestSelect_LabelValue_LoadOnlyIDAndValue(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBLabelValues(10000)
	require.NoError(t, batchInsert(db, items, 1000))

	lv := &labelValue{
		org:       newTestORG(db),
		valueToID: make(map[string]int),
	}

	err := lv.refresh()
	require.NoError(t, err)

	snapshot := lv.GetValueToID()
	assert.Len(t, snapshot, 10000)
	for i := 0; i < 10000; i++ {
		id, ok := lv.GetIDByValue(fmt.Sprintf("lv_%d", i))
		assert.True(t, ok, "value lv_%d should exist", i)
		assert.Equal(t, i+1, id)
	}
}

func TestSelect_Label_LoadOnlyIDNameValue(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBLabels(5000)
	require.NoError(t, batchInsert(db, items, 1000))

	l := &label{
		org:     newTestORG(db),
		keyToID: make(map[LabelKey]int),
	}

	err := l.refresh()
	require.NoError(t, err)

	snapshot := l.GetKeyToID()
	assert.Len(t, snapshot, 5000)
	for i := 0; i < 5000; i++ {
		_, ok := l.GetIDByKey(NewLabelKey(fmt.Sprintf("n_%d", i), fmt.Sprintf("v_%d", i)))
		assert.True(t, ok, "label n_%d/v_%d should exist", i, i)
	}
}

func TestSelect_Layout_LoadOnlyNeededColumns(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBLayouts(500)
	require.NoError(t, batchInsert(db, items, 200))

	mll := &metricAndAPPLabelLayout{
		org:              newTestORG(db),
		layoutKeyToIndex: make(map[LayoutKey]uint8),
	}

	err := mll.refresh()
	require.NoError(t, err)

	snapshot := mll.GetLayoutKeyToIndex()
	assert.NotEmpty(t, snapshot)
	for _, item := range items {
		idx, ok := mll.GetIndexByKey(NewLayoutKey(item.MetricName, item.APPLabelName))
		assert.True(t, ok, "layout %s/%s should exist", item.MetricName, item.APPLabelName)
		assert.Equal(t, item.APPLabelColumnIndex, idx)
	}
}

// ============================================================================
// 覆盖式 refresh + Select 联合测试：验证 swap 后旧条目消失
// ============================================================================

func TestSelect_Label_RefreshDiscardsDeletedRows(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	// 第一轮：插入 200 条并 refresh
	items := generateDBLabels(200)
	require.NoError(t, batchInsert(db, items, 100))

	l := &label{org: newTestORG(db), keyToID: make(map[LabelKey]int)}
	require.NoError(t, l.refresh())
	assert.Equal(t, 200, len(l.GetKeyToID()))

	// 模拟 Cleaner 删除后 100 条
	db.Where("id > ?", 100).Delete(&metadbmodel.PrometheusLabel{})

	// 第二轮 refresh — 应该只剩 100 条
	require.NoError(t, l.refresh())
	assert.Equal(t, 100, len(l.GetKeyToID()))

	// 被删除的条目不可访问
	_, ok := l.GetIDByKey(NewLabelKey("n_150", "v_150"))
	assert.False(t, ok, "deleted label should not exist after refresh")
}

func TestSelect_MetricName_RefreshDiscardsDeletedRows(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	items := generateDBMetricNames(200)
	require.NoError(t, batchInsert(db, items, 100))

	mn := &metricName{org: newTestORG(db), nameToID: make(map[string]int), idToName: make(map[int]string)}
	require.NoError(t, mn.refresh())
	assert.Equal(t, 200, len(mn.GetNameToID()))

	// 删除后半部分
	db.Where("id > ?", 100).Delete(&metadbmodel.PrometheusMetricName{})

	require.NoError(t, mn.refresh())
	assert.Equal(t, 100, len(mn.GetNameToID()))

	_, ok := mn.GetIDByName("metric_150")
	assert.False(t, ok)
}

// ============================================================================
// 大数据量测试：label_value 100 万行
// ============================================================================

func TestSelect_LabelValue_1M_Refresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1M label_value test in short mode")
	}

	const N = 1_000_000
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	// ---- 写入 100 万行 ----
	t.Logf("inserting %d label_values into SQLite...", N)
	insertStart := time.Now()
	items := generateDBLabelValues(N)
	require.NoError(t, batchInsert(db, items, 5000))
	t.Logf("insert completed in %v", time.Since(insertStart))

	// 验证行数
	var count int64
	db.Model(&metadbmodel.PrometheusLabelValue{}).Count(&count)
	require.Equal(t, int64(N), count)

	// ---- refresh（Select 精简列）性能测试 ----
	lv := &labelValue{org: newTestORG(db), valueToID: make(map[string]int)}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	refreshStart := time.Now()
	err := lv.refresh()
	refreshDuration := time.Since(refreshStart)
	require.NoError(t, err)

	var m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m2)

	snapshot := lv.GetValueToID()
	assert.Len(t, snapshot, N)
	t.Logf("refresh %d label_values: duration=%v, HeapInuse before=%dMB after=%dMB",
		N, refreshDuration, m1.HeapInuse/1024/1024, m2.HeapInuse/1024/1024)

	// ---- 正确性抽检 ----
	for _, idx := range []int{0, 1, 999, 10000, 99999, 500000, 999999} {
		id, ok := lv.GetIDByValue(fmt.Sprintf("lv_%d", idx))
		assert.True(t, ok, "lv_%d should exist", idx)
		assert.Equal(t, idx+1, id)
	}

	// ---- 模拟 Cleaner 删除 90% 数据后 refresh ----
	t.Log("deleting 90% rows to test shrink...")
	db.Where("id > ?", N/10).Delete(&metadbmodel.PrometheusLabelValue{})

	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)

	refreshStart2 := time.Now()
	require.NoError(t, lv.refresh())
	refreshDuration2 := time.Since(refreshStart2)

	runtime.GC()
	runtime.GC()
	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)

	remaining := len(lv.GetValueToID())
	assert.Equal(t, N/10, remaining)
	t.Logf("refresh after delete: remaining=%d, duration=%v, HeapInuse before=%dMB after=%dMB",
		remaining, refreshDuration2, m3.HeapInuse/1024/1024, m4.HeapInuse/1024/1024)

	// 被删除的条目不可访问
	_, ok := lv.GetIDByValue(fmt.Sprintf("lv_%d", N-1))
	assert.False(t, ok, "deleted value should not exist after refresh")
}

// ============================================================================
// 大数据量测试：label 50 万行（Name+Value 组合键）
// ============================================================================

func TestSelect_Label_500K_Refresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 500K label test in short mode")
	}

	const N = 500_000
	db := setupTestDB(t)
	defer cleanupTestDB(t)

	t.Logf("inserting %d labels into SQLite...", N)
	insertStart := time.Now()
	items := generateDBLabels(N)
	require.NoError(t, batchInsert(db, items, 5000))
	t.Logf("insert completed in %v", time.Since(insertStart))

	l := &label{org: newTestORG(db), keyToID: make(map[LabelKey]int)}

	refreshStart := time.Now()
	err := l.refresh()
	refreshDuration := time.Since(refreshStart)
	require.NoError(t, err)

	snapshot := l.GetKeyToID()
	assert.Len(t, snapshot, N)
	t.Logf("refresh %d labels: duration=%v", N, refreshDuration)

	// 抽检
	for _, idx := range []int{0, 100, 9999, 250000, 499999} {
		_, ok := l.GetIDByKey(NewLabelKey(fmt.Sprintf("n_%d", idx), fmt.Sprintf("v_%d", idx)))
		assert.True(t, ok, "label n_%d/v_%d should exist", idx, idx)
	}
}

// ============================================================================
// Benchmark：对比 Select 列裁剪 vs 全列加载的 refresh 性能
// ============================================================================

func BenchmarkRefresh_LabelValue_WithSelect(b *testing.B) {
	db := setupTestDB(b)
	defer cleanupTestDB(b)

	const N = 100_000
	items := generateDBLabelValues(N)
	require.NoError(b, batchInsert(db, items, 5000))

	lv := &labelValue{org: newTestORG(db), valueToID: make(map[string]int)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lv.refresh()
	}
}

func BenchmarkRefresh_LabelValue_WithoutSelect(b *testing.B) {
	db := setupTestDB(b)
	defer cleanupTestDB(b)

	const N = 100_000
	items := generateDBLabelValues(N)
	require.NoError(b, batchInsert(db, items, 5000))

	org := newTestORG(db)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 模拟不加 Select 的全列加载
		var labelValues []*metadbmodel.PrometheusLabelValue
		org.DB.Find(&labelValues)
		newMap := make(map[string]int, len(labelValues))
		for _, item := range labelValues {
			newMap[item.Value] = item.ID
		}
	}
}

func BenchmarkRefresh_Label_WithSelect(b *testing.B) {
	db := setupTestDB(b)
	defer cleanupTestDB(b)

	const N = 100_000
	items := generateDBLabels(N)
	require.NoError(b, batchInsert(db, items, 5000))

	l := &label{org: newTestORG(db), keyToID: make(map[LabelKey]int)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.refresh()
	}
}

func BenchmarkRefresh_Label_WithoutSelect(b *testing.B) {
	db := setupTestDB(b)
	defer cleanupTestDB(b)

	const N = 100_000
	items := generateDBLabels(N)
	require.NoError(b, batchInsert(db, items, 5000))

	org := newTestORG(db)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var labels []*metadbmodel.PrometheusLabel
		org.DB.Find(&labels)
		newMap := make(map[LabelKey]int, len(labels))
		for _, item := range labels {
			newMap[NewLabelKey(item.Name, item.Value)] = item.ID
		}
	}
}
