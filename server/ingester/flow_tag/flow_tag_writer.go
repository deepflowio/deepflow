package flow_tag

import (
	"bytes"
	"fmt"
	"strconv"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/hmap/lru"
	//slowlru "github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

const (
	FLOW_TAG_CACHE_INIT_SIZE = 1 << 14
	MIN_FLUSH_CACHE_TIMEOUT  = 60
)

type Counter struct {
	NewFieldCount        int64 `statsd:"new-field-count"`
	NewFieldValueCount   int64 `statsd:"new-field-value-count"`
	FieldCacheCount      int64 `statsd:"field-cache-count"`
	FieldValueCacheCount int64 `statsd:"field-value-cache-count"`
	SeriesCacheCount     int64 `statsd:"series-cache-count"`
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

type SeriesCache struct {
	Cache      map[string]uint32
	Limit      uint32
	Buffers    []bytes.Buffer
	Timestamps []uint32
}

func NewSeriesCache(limit uint32) *SeriesCache {
	buffers := []bytes.Buffer{bytes.Buffer{}}
	buffers[0].Grow(1 << 20)

	return &SeriesCache{
		Cache:   make(map[string]uint32),
		Limit:   limit,
		Buffers: buffers,
	}
}

func (c *SeriesCache) GetByteBuffer() *bytes.Buffer {
	buf := &c.Buffers[len(c.Buffers)-1]
	if buf.Len() >= 1<<20-2048 {
		c.Buffers = append(c.Buffers, bytes.Buffer{})
		buf = &c.Buffers[len(c.Buffers)-1]
		buf.Grow(1 << 20)
	}
	return buf
}

type FlowTagCache struct {
	FieldCache        *lru.U128LRU
	FieldValueCache   *lru.U128LRU
	CacheFlushTimeout uint32

	SeriesCache *SeriesCache

	// temporary buffers for generating new flow_tags
	FlowTagInfoBuffer    FlowTagInfo
	FlowTagInfoKeyBuffer FlowTagInfoKey
	Fields               []interface{}
	FieldValues          []interface{}
}

func NewFlowTagCache(name string, cacheFlushTimeout, cacheMaxSize, seriesCacheMaxSize uint32) *FlowTagCache {
	return &FlowTagCache{
		FieldCache:      lru.NewU128LRU(name+"-field", int(cacheMaxSize)>>6, int(cacheMaxSize)>>3),
		FieldValueCache: lru.NewU128LRU(name+"-field_value", int(cacheMaxSize)>>3, int(cacheMaxSize)),
		// SeriesCache:     slowlru.NewCache(int(seriesCacheMaxSize)),
		SeriesCache: NewSeriesCache(uint32(seriesCacheMaxSize)),

		CacheFlushTimeout: cacheFlushTimeout,
	}
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

		Cache: NewFlowTagCache(
			fmt.Sprintf("%s-%s-%d", name, srcDB, decoderIndex),
			config.FlowTagCacheFlushTimeout,
			config.FlowTagCacheMaxSize,
			config.ExtMetricsSeriesCacheMaxSize,
		),
		counter: &Counter{},
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
	counter.FieldCacheCount = int64(w.Cache.FieldCache.Size())
	counter.FieldValueCacheCount = int64(w.Cache.FieldValueCache.Size())
	counter.SeriesCacheCount = int64(len(w.Cache.SeriesCache.Cache))
	return counter
}
