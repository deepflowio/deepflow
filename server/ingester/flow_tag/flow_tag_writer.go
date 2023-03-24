package flow_tag

import (
	"fmt"
	"strconv"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/lru"
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
	FieldCache, FieldValueCache *lru.Cache
	CacheFlushTimeout           uint32

	// temporary buffers for generating new flow_tags
	FlowTagInfoBuffer FlowTagInfo
	Fields            []interface{}
	FieldValues       []interface{}
}

func NewFlowTagCache(cacheFlushTimeout, cacheMaxSize uint32) *FlowTagCache {
	return &FlowTagCache{
		FieldCache:        lru.NewCache(int(cacheMaxSize)),
		FieldValueCache:   lru.NewCache(int(cacheMaxSize)),
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

		Cache:   NewFlowTagCache(config.FlowTagCacheFlushTimeout, config.FlowTagCacheMaxSize),
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
	counter.FieldCacheCount = int64(w.Cache.FieldCache.Len())
	counter.FieldValueCacheCount = int64(w.Cache.FieldValueCache.Len())
	return counter
}
