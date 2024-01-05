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

package flow_tag

import (
	"fmt"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	lru128 "github.com/deepflowio/deepflow/server/libs/hmap/lru"
	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

const (
	FLOW_TAG_CACHE_INIT_SIZE = 1 << 14
	MIN_FLUSH_CACHE_TIMEOUT  = 60
	PROMETHEUS_KEYWORD       = "prometheus"
)

type Counter struct {
	NewFieldCount        int64 `statsd:"new-field-count"`
	NewFieldValueCount   int64 `statsd:"new-field-value-count"`
	FieldCacheCount      int64 `statsd:"field-cache-count"`
	FieldValueCacheCount int64 `statsd:"field-value-cache-count"`
}

type FlowTagWriter struct {
	ckdbAddrs    []string
	ckdbUsername string
	ckdbPassword string
	writerConfig *config.CKWriterConfig

	ckwriters [TagTypeMax]*ckwriter.CKWriter

	Cache *FlowTagCache

	counter *Counter
	utils.Closable
}

type FlowTagCache struct {
	Id                          int
	FieldCache, FieldValueCache *lru.Cache[FlowTagInfo, uint32]
	CacheFlushTimeout           uint32

	// only for prometheus
	PrometheusFieldCache, PrometheusFieldValueCache *lru128.U128LRU

	// temporary buffers for generating new flow_tags
	FlowTagInfoBuffer FlowTagInfo
	Fields            []interface{}
	FieldValues       []interface{}
}

func NewFlowTagCache(name string, id int, cacheFlushTimeout, cacheMaxSize uint32) *FlowTagCache {
	c := &FlowTagCache{
		Id:                id,
		CacheFlushTimeout: cacheFlushTimeout,
	}

	// Prometheus data can be converted into IDs so use LRU128, others use ordinary LRU
	if strings.Contains(name, PROMETHEUS_KEYWORD) {
		c.PrometheusFieldCache = lru128.NewU128LRU(fmt.Sprintf("%s-flow-tag-field_%d", name, id), int(cacheMaxSize)>>3, int(cacheMaxSize))
		c.PrometheusFieldValueCache = lru128.NewU128LRU(fmt.Sprintf("%s-flow-tag-field-value_%d", name, id), int(cacheMaxSize)>>3, int(cacheMaxSize))
	} else {
		c.FieldCache = lru.NewCache[FlowTagInfo, uint32](int(cacheMaxSize))
		c.FieldValueCache = lru.NewCache[FlowTagInfo, uint32](int(cacheMaxSize))
	}
	return c
}

func NewFlowTagWriter(
	decoderIndex int,
	name string,
	srcDB string,
	ttl int,
	partition ckdb.TimeFuncType,
	config *config.Config,
	writerConfig *config.CKWriterConfig) (*FlowTagWriter, error) {
	w := &FlowTagWriter{
		ckdbAddrs:    config.CKDB.ActualAddrs,
		ckdbUsername: config.CKDBAuth.Username,
		ckdbPassword: config.CKDBAuth.Password,
		writerConfig: writerConfig,
		Cache:        NewFlowTagCache(name, decoderIndex, config.FlowTagCacheFlushTimeout, config.FlowTagCacheMaxSize),
		counter:      &Counter{},
	}
	t := FlowTag{}
	var err error
	for _, tagType := range []TagType{TagField, TagFieldValue} {
		tableName := fmt.Sprintf("%s_%s", srcDB, tagType.String())
		t.FieldValue = ""
		if tagType == TagFieldValue {
			t.FieldValue = "x" // Assign a value to the FieldValue field to correctly identify the type of FlowTag.
		}
		w.ckwriters[tagType], err = ckwriter.NewCKWriter(
			w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
			fmt.Sprintf("%s-%s-%d", name, tableName, decoderIndex),
			config.CKDB.TimeZone,
			t.GenCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, tableName, ttl, partition),
			w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
		if err != nil {
			return nil, err
		}
		w.ckwriters[tagType].Run()
	}

	common.RegisterCountableForIngester("flow_tag_writer", w, stats.OptionStatTags{"type": name, "decoder_index": strconv.Itoa(decoderIndex)})
	return w, nil
}

func (w *FlowTagWriter) Write(t TagType, values ...interface{}) {
	w.ckwriters[t].Put(values...)
}

func (w *FlowTagWriter) WriteFieldsAndFieldValuesInCache() {
	if len(w.Cache.Fields) != 0 {
		w.ckwriters[TagField].Put(w.Cache.Fields...)
		w.counter.NewFieldCount += int64(len(w.Cache.Fields))
	}
	if len(w.Cache.FieldValues) != 0 {
		w.ckwriters[TagFieldValue].Put(w.Cache.FieldValues...)
		w.counter.NewFieldValueCount += int64(len(w.Cache.FieldValues))
	}
}

func (w *FlowTagWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	if w.Cache.FieldCache != nil {
		counter.FieldCacheCount = int64(w.Cache.FieldCache.Len())
	} else {
		counter.FieldCacheCount = int64(w.Cache.PrometheusFieldCache.Size())
	}
	if w.Cache.FieldValueCache != nil {
		counter.FieldValueCacheCount = int64(w.Cache.FieldValueCache.Len())
	} else {
		counter.FieldValueCacheCount = int64(w.Cache.PrometheusFieldValueCache.Size())
	}
	return counter
}
