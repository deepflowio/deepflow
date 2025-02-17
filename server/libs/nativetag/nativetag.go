/*
 * Copyright (c) 2025 Yunshan Networks
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

package nativetag

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/ClickHouse/ch-go/proto"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("nativetag")

type NativeTagTable uint8

const (
	APPLICATION_LOG NativeTagTable = iota
	EVENT_EVENT
	EVENT_PERF_EVENT
	L7_FLOW_LOG
	DEEPFLOW_ADMIN
	DEEPFLOW_TENANT
	EXT_METRICS
	PROFILE

	MAX_NATIVE_TAG_TABLE
)

var NativeTagDatabaseNames = [MAX_NATIVE_TAG_TABLE]string{
	APPLICATION_LOG:  "application_log",
	EVENT_EVENT:      "event",
	EVENT_PERF_EVENT: "event",
	L7_FLOW_LOG:      "flow_log",
	DEEPFLOW_ADMIN:   "deepflow_admin",
	DEEPFLOW_TENANT:  "deepflow_tenant",
	EXT_METRICS:      "ext_metrics",
	PROFILE:          "profile",
}

var NativeTagTableNames = [MAX_NATIVE_TAG_TABLE]string{
	APPLICATION_LOG:  "log",
	EVENT_EVENT:      "event",
	EVENT_PERF_EVENT: "perf_event",
	L7_FLOW_LOG:      "l7_flow_log",
	DEEPFLOW_ADMIN:   "deepflow_server",
	DEEPFLOW_TENANT:  "deepflow_collector",
	EXT_METRICS:      "metrics",
	PROFILE:          "in_process",
}

func (t NativeTagTable) Database() string {
	return NativeTagDatabaseNames[t]
}

func (t NativeTagTable) Table() string {
	return NativeTagTableNames[t]
}

func (t NativeTagTable) LocalTable() string {
	return t.Table() + "_local"
}

func ToNativeTagTable(db, table string) (NativeTagTable, error) {
	for i := APPLICATION_LOG; i < MAX_NATIVE_TAG_TABLE; i++ {
		if i.Database() == db && i.Table() == table {
			return i, nil
		}
	}
	return MAX_NATIVE_TAG_TABLE, fmt.Errorf("unsupport db %s, table %s", db, table)
}

type NativeTagType uint8

const (
	NATIVE_TAG_STRING NativeTagType = iota
	NATIVE_TAG_INT64
	NATIVE_TAG_FLOAT64
)

func (t NativeTagType) String() string {
	switch t {
	case NATIVE_TAG_STRING:
		return ckdb.String.String()
	case NATIVE_TAG_INT64:
		return ckdb.Int64.String()
	case NATIVE_TAG_FLOAT64:
		return ckdb.Float64.String()
	}
	return "unsupport native tag type"
}

func (t NativeTagType) IndexString() string {
	switch t {
	case NATIVE_TAG_STRING:
		return ckdb.IndexBloomfilter.String()
	default:
		return ckdb.IndexMinmax.String()
	}
}

type NativeTagOP uint8

const (
	NATIVE_TAG_ADD NativeTagOP = iota
	NATIVE_TAG_DELETE
)

func (o NativeTagOP) String() string {
	switch o {
	case NATIVE_TAG_ADD:
		return "add"
	case NATIVE_TAG_DELETE:
		return "delete"
	default:
		return "unknown op"
	}
}

var NativeTags [ckdb.MAX_ORG_ID + 1][MAX_NATIVE_TAG_TABLE]*NativeTag

type NativeTag struct {
	Db             string
	Table          string
	Version        uint32
	AttributeNames []string
	ColumnNames    []string
	ColumnTypes    []NativeTagType
}

func (t *NativeTag) Add(add *NativeTag) {
	if add == nil {
		return
	}
	for i, attributeName := range add.AttributeNames {
		index := IndexOf(t.AttributeNames, attributeName)
		// if it already exists, overwrite
		if index > -1 {
			if t.ColumnNames[index] != add.ColumnNames[i] {
				t.ColumnNames[index] = add.ColumnNames[i]
				log.Warningf("native tag overwrite attributeName %s column name from %s to %s", attributeName, t.ColumnNames[index], add.ColumnNames[i])
			}
			if t.ColumnTypes[index] != add.ColumnTypes[i] {
				t.ColumnTypes[index] = add.ColumnTypes[i]
				log.Warningf("native tag overwrite attributeName %s column type from %s to %s", attributeName, t.ColumnTypes[index], add.ColumnTypes[i])
			}
		} else {
			t.AttributeNames = append(t.AttributeNames, attributeName)
			t.ColumnNames = append(t.ColumnNames, add.ColumnNames[i])
			t.ColumnTypes = append(t.ColumnTypes, add.ColumnTypes[i])
			log.Infof("native tag add attributeName %s, column name %s, column type %s", attributeName, add.ColumnNames[i], add.ColumnTypes[i])
		}
	}
}

func RemoveItem[T any](slice []T, index int) ([]T, error) {
	if index < 0 || index >= len(slice) {
		return nil, fmt.Errorf("index out of slice length, index %d, slice length %d", index, len(slice))
	}

	copy(slice[index:], slice[index+1:])
	slice = slice[:len(slice)-1]

	return slice, nil
}

func (t *NativeTag) Delete(del *NativeTag) {
	if del == nil {
		return
	}
	for i, attributeName := range del.AttributeNames {
		index := IndexOf(t.AttributeNames, attributeName)
		// if it exists, delete
		if index > -1 {
			t.AttributeNames, _ = RemoveItem(t.AttributeNames, index)
			t.ColumnNames, _ = RemoveItem(t.ColumnNames, index)
			t.ColumnTypes, _ = RemoveItem(t.ColumnTypes, index)
			log.Infof("native tag delete attributeName %s, column name %s, column type %s", attributeName, del.ColumnNames[i], del.ColumnTypes[i])
		} else {
			log.Warningf("native tag not exist attributeName %s, column name %s, column type %s", attributeName, del.ColumnNames[i], del.ColumnTypes[i])
		}
	}
}

func UpdateNativeTag(op NativeTagOP, orgId uint16, nativeTag *NativeTag) {
	tableId, err := ToNativeTagTable(nativeTag.Db, nativeTag.Table)
	if err != nil {
		log.Error(err)
		return
	}

	oldNativeTag := NativeTags[orgId][tableId]
	if oldNativeTag == nil {
		oldNativeTag = &NativeTag{}
	}

	if op == NATIVE_TAG_ADD {
		oldNativeTag.Add(nativeTag)
	} else if op == NATIVE_TAG_DELETE {
		oldNativeTag.Delete(nativeTag)
	}
	oldNativeTag.Version = oldNativeTag.Version + 1

	NativeTags[orgId][tableId] = oldNativeTag
	log.Infof("after %s orgid %d, table %s, native tag: %+v", op, orgId, tableId.Table(), oldNativeTag)
}

func CKAddNativeTag(isByConity bool, conn *sql.DB, orgId uint16, nativeTag *NativeTag) error {
	tableId, err := ToNativeTagTable(nativeTag.Db, nativeTag.Table)
	if err != nil {
		log.Error(err)
		return err
	}

	for i, columnName := range nativeTag.ColumnNames {
		tableGlobal := fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN %s %s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.Table(), columnName, nativeTag.ColumnTypes[i])
		tableLocal := fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN %s %s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.LocalTable(), columnName, nativeTag.ColumnTypes[i])

		indexGlobal := fmt.Sprintf("ALTER TABLE %s.`%s` ADD INDEX IF NOT EXISTS idx_%s %s TYPE %s GRANULARITY 2",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.Table(), columnName, columnName, nativeTag.ColumnTypes[i].IndexString())
		indexLocal := fmt.Sprintf("ALTER TABLE %s.`%s` ADD INDEX IF NOT EXISTS idx_%s %s TYPE %s GRANULARITY 2",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.LocalTable(), columnName, columnName, nativeTag.ColumnTypes[i].IndexString())

		sqls := []string{tableGlobal}
		if isByConity {
			sqls = append(sqls, indexGlobal)
		} else {
			sqls = append(sqls, tableLocal, indexLocal)
		}

		for _, sql := range sqls {
			log.Infof("add native tag: %s", sql)
			_, err := conn.Exec(sql)
			if err != nil {
				// if it has already been added, you need to skip the error
				if strings.Contains(err.Error(), "column with this name already exists") {
					log.Infof("db: %s, table: %s error: %s", tableId.Database(), tableId.Table(), err)
					continue
				}
				return err
			}
		}
	}
	return nil
}

func CKDropNativeTag(isByConity bool, conn *sql.DB, orgId uint16, nativeTag *NativeTag) error {
	if nativeTag == nil {
		return nil
	}
	tableId, err := ToNativeTagTable(nativeTag.Db, nativeTag.Table)
	if err != nil {
		log.Error(err)
		return err
	}
	for _, columnName := range nativeTag.ColumnNames {
		tableGlobal := fmt.Sprintf("ALTER TABLE %s.`%s` DROP COLUMN IF EXISTS %s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.Table(), columnName)
		tableLocal := fmt.Sprintf("ALTER TABLE %s.`%s` DROP COLUMN IF EXISTS %s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.LocalTable(), columnName)

		indexGlobal := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX IF EXISTS idx_%s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.Table(), columnName)
		indexLocal := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX IF EXISTS idx_%s",
			ckdb.OrgDatabasePrefix(orgId)+tableId.Database(), tableId.LocalTable(), columnName)

		sqls := []string{}
		if isByConity {
			sqls = []string{indexGlobal, tableGlobal}
		} else {
			sqls = []string{indexLocal, tableGlobal, tableLocal}
		}

		for _, sql := range sqls {
			log.Infof("drop native tag: %s", sql)
			_, err := conn.Exec(sql)
			if err != nil {
				log.Info(err)
			}
		}
	}
	return nil
}

func GetAllNativeTags() [ckdb.MAX_ORG_ID + 1][MAX_NATIVE_TAG_TABLE]*NativeTag {
	return NativeTags
}

func GetNativeTags(orgId uint16, tableId NativeTagTable) *NativeTag {
	return NativeTags[orgId][tableId]
}

func GetTableNativeTagsVersion(orgId uint16, tableId NativeTagTable) uint32 {
	nativeTag := NativeTags[orgId][tableId]
	if nativeTag == nil {
		return 0
	}
	return nativeTag.Version
}

func GetTableNativeTagsColumnBlock(orgId uint16, tableId NativeTagTable) *NativeTagsBlock {
	nativeTag := NativeTags[orgId][tableId]
	if nativeTag == nil {
		return nil
	}
	return nativeTag.NewColumnBlock()
}

type NativeTagsBlock struct {
	TagNames, StringColumnNames []string
	ColTags                     []proto.ColStr

	IntMetricsNames, IntColumnNames []string
	ColIntMetrics                   []proto.ColInt64

	FloatMetricsNames, FloatColumnNames []string
	ColFloatMetrics                     []proto.ColFloat64
}

func (b *NativeTagsBlock) Reset() {
	for i := range b.ColTags {
		b.ColTags[i].Reset()
	}
	for i := range b.ColIntMetrics {
		b.ColIntMetrics[i].Reset()
	}
	for i := range b.ColFloatMetrics {
		b.ColFloatMetrics[i].Reset()
	}
}

func (b *NativeTagsBlock) ToInput(input proto.Input) proto.Input {
	if len(b.TagNames) != len(b.ColTags) ||
		len(b.IntMetricsNames) != len(b.ColIntMetrics) ||
		len(b.FloatMetricsNames) != len(b.ColFloatMetrics) {
		log.Warningf("invalid native block length: %d %d, %d %d, %d %d",
			len(b.TagNames), len(b.ColTags), len(b.IntMetricsNames), len(b.ColIntMetrics), len(b.FloatMetricsNames), len(b.ColFloatMetrics))
		return input
	}
	for i := range b.ColTags {
		input = append(input, proto.InputColumn{Name: b.StringColumnNames[i], Data: &b.ColTags[i]})
	}
	for i := range b.ColIntMetrics {
		input = append(input, proto.InputColumn{Name: b.IntColumnNames[i], Data: &b.ColIntMetrics[i]})
	}
	for i := range b.ColFloatMetrics {
		input = append(input, proto.InputColumn{Name: b.FloatColumnNames[i], Data: &b.ColFloatMetrics[i]})
	}
	return input
}

func IndexOf(slice []string, str string) int {
	for i, v := range slice {
		if v == str {
			return i
		}
	}
	return -1
}

func (b *NativeTagsBlock) AppendToColumnBlock(attributeNames, attributeValues, metricsNames []string, metricsValues []float64) {
	for i, name := range b.TagNames {
		if index := IndexOf(attributeNames, name); index >= 0 {
			b.ColTags[i].Append(attributeValues[index])
		} else {
			b.ColTags[i].Append("")
		}
	}
	for i, name := range b.IntMetricsNames {
		if index := IndexOf(attributeNames, name); index >= 0 {
			valueInt64, _ := strconv.ParseInt(attributeValues[index], 10, 64)
			b.ColIntMetrics[i].Append(valueInt64)
		} else if index := IndexOf(metricsNames, name); index >= 0 {
			valueInt64 := int64(metricsValues[index])
			b.ColIntMetrics[i].Append(valueInt64)
		} else {
			b.ColIntMetrics[i].Append(0)
		}
	}

	for i, name := range b.FloatMetricsNames {
		if index := IndexOf(attributeNames, name); index >= 0 {
			valueFloat64, _ := strconv.ParseFloat(attributeValues[index], 64)
			b.ColFloatMetrics[i].Append(valueFloat64)
		} else if index := IndexOf(metricsNames, name); index >= 0 {
			b.ColFloatMetrics[i].Append(metricsValues[index])
		} else {
			b.ColFloatMetrics[i].Append(0)
		}
	}
}

func (t *NativeTag) NewColumnBlock() *NativeTagsBlock {
	block := &NativeTagsBlock{}
	for i, name := range t.AttributeNames {
		switch t.ColumnTypes[i] {
		case NATIVE_TAG_STRING:
			block.TagNames = append(block.TagNames, name)
			block.StringColumnNames = append(block.StringColumnNames, t.ColumnNames[i])
			block.ColTags = append(block.ColTags, proto.ColStr{})
		case NATIVE_TAG_INT64:
			block.IntMetricsNames = append(block.IntMetricsNames, name)
			block.IntColumnNames = append(block.IntColumnNames, t.ColumnNames[i])
			block.ColIntMetrics = append(block.ColIntMetrics, proto.ColInt64{})
		case NATIVE_TAG_FLOAT64:
			block.FloatMetricsNames = append(block.FloatMetricsNames, name)
			block.FloatColumnNames = append(block.FloatColumnNames, t.ColumnNames[i])
			block.ColFloatMetrics = append(block.ColFloatMetrics, proto.ColFloat64{})
		}
	}
	return block
}
