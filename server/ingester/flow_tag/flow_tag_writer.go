package flow_tag

import (
	"fmt"
	"sync"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

const (
	FLOW_TAG_CACHE_INIT_SIZE = 1 << 14
	MIN_FLUSH_CACHE_TIMEOUT  = 60
	CACHE_FLUSH_WRITE_COUNT  = 100 << 10 // 100k
)

type Counter struct {
	FieldCount              int64 `statsd:"field-count"`
	FieldValueCount         int64 `statsd:"field-value-count"`
	FieldCacheCount         int64 `statsd:"field-cache-count"`
	FieldValueCacheCount    int64 `statsd:"field-value-cache-count"`
	FieldCacheHitCount      int64 `statsd:"field-cache-hit-count"`
	FieldValueCacheHitCount int64 `statsd:"field-value-cache-hit-count"`
}

type FlowTagWriter struct {
	ckdbAddrs    []string
	ckdbUsername string
	ckdbPassword string
	writerConfig *config.CKWriterConfig

	ckwriters      [TagTypeMax]*ckwriter.CKWriter
	valueWriter    *ckwriter.CKWriter
	cache          *FlowTagCache
	fieldsBuf      []interface{}
	fieldValuesBuf []interface{}

	counter *Counter
	utils.Closable
}

type FlowTagCache struct {
	fieldCache, fieldValueCache map[FlowTagInfo]*FlowTag
	fieldLock, fieldValueLock   sync.Mutex

	lastFieldFlushTime, lastFieldValueFlushTime int64
	cacheFlushTimeout                           int64
	cacheMaxSize                                int
}

func NewFlowTagCache(cacheFlushTimeout, cacheMaxSize uint32) *FlowTagCache {
	return &FlowTagCache{
		fieldCache:              make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE),
		fieldValueCache:         make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE),
		lastFieldFlushTime:      time.Now().Unix(),
		lastFieldValueFlushTime: time.Now().Unix(),
		cacheFlushTimeout:       int64(cacheFlushTimeout),
		cacheMaxSize:            int(cacheMaxSize),
	}
}

func (c *FlowTagCache) CacheOrDropFields(fields []interface{}) []interface{} {
	c.fieldLock.Lock()
	defer c.fieldLock.Unlock()
	j := 0
	for _, v := range fields {
		if field, ok := v.(*FlowTag); ok {
			if _, ok := c.fieldCache[field.FlowTagInfo]; ok {
				field.Release()
			} else {
				fields[j] = v
				j++
				field.AddReferenceCount()
				c.fieldCache[field.FlowTagInfo] = field
			}
		}
	}
	return fields[:j]
}

func (c *FlowTagCache) CacheOrDropFieldValues(values []interface{}) []interface{} {
	c.fieldValueLock.Lock()
	defer c.fieldValueLock.Unlock()
	j := 0
	for _, v := range values {
		if fieldValue, ok := v.(*FlowTag); ok {
			if value, ok := c.fieldValueCache[fieldValue.FlowTagInfo]; ok {
				value.fieldValueCount++
				fieldValue.Release()
			} else {
				values[j] = v
				j++
				fieldValue.AddReferenceCount()
				c.fieldValueCache[fieldValue.FlowTagInfo] = fieldValue
			}
		}
	}
	return values[:j]
}

func (c *FlowTagCache) CheckOrFlushFields() []interface{} {
	timeDiff := time.Now().Unix() - c.lastFieldFlushTime
	if (timeDiff < c.cacheFlushTimeout &&
		len(c.fieldCache) < c.cacheMaxSize) ||
		timeDiff < MIN_FLUSH_CACHE_TIMEOUT {
		return nil
	}
	c.fieldLock.Lock()
	defer c.fieldLock.Unlock()
	fields := make([]interface{}, 0, len(c.fieldCache))
	for _, v := range c.fieldCache {
		fields = append(fields, v)
	}
	c.fieldCache = make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE)
	c.lastFieldFlushTime = time.Now().Unix()

	return fields
}

func (c *FlowTagCache) CheckOrFlushFieldValues() []interface{} {
	timeDiff := time.Now().Unix() - c.lastFieldValueFlushTime
	if (timeDiff < c.cacheFlushTimeout &&
		len(c.fieldValueCache) < c.cacheMaxSize) ||
		timeDiff < MIN_FLUSH_CACHE_TIMEOUT {
		return nil
	}
	c.fieldValueLock.Lock()
	defer c.fieldValueLock.Unlock()
	fieldValues := make([]interface{}, 0, len(c.fieldValueCache))
	for _, v := range c.fieldValueCache {
		v.fieldValueCount--
		fieldValues = append(fieldValues, v)
	}
	c.fieldValueCache = make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE)
	c.lastFieldValueFlushTime = time.Now().Unix()

	return fieldValues
}

func NewFlowTagWriter(
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

		cache:   NewFlowTagCache(config.FlowTagCacheFlushTimeout, config.FlowTagCacheMaxSize),
		counter: &Counter{},
	}
	t := FlowTag{}
	var err error
	for _, tagType := range []TagType{TagField, TagFieldValue} {
		tableName := fmt.Sprintf("%s_%s", srcDB, tagType.String())
		t.hasFieldValue = false
		if tagType == TagFieldValue {
			t.hasFieldValue = true
		}
		w.ckwriters[tagType], err = ckwriter.NewCKWriter(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
			fmt.Sprintf("%s_%s", name, tableName), t.GenCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, tableName, ttl, partition), w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
		if err != nil {
			return nil, err
		}
		w.ckwriters[tagType].Run()
	}

	common.RegisterCountableForIngester("flow_tag_writer", w, stats.OptionStatTags{"type": name})
	return w, nil
}

func (w *FlowTagWriter) Write(t TagType, values ...interface{}) {
	w.ckwriters[t].Put(values...)
}

func (w *FlowTagWriter) WriteSmoothly(t TagType, values []interface{}) {
	for i := 0; i < len(values); i += CACHE_FLUSH_WRITE_COUNT {
		endIndex := i + CACHE_FLUSH_WRITE_COUNT
		if i+CACHE_FLUSH_WRITE_COUNT > len(values) {
			endIndex = len(values)
		}
		w.ckwriters[t].Put(values[i:endIndex]...)
		time.Sleep(10 * time.Second)
	}
}

func (w *FlowTagWriter) WriteFieldsAndFieldValues(fields, fieldValues []interface{}) {
	fieldsCount, fieldValuesCount := len(fields), len(fieldValues)
	fields = w.cache.CacheOrDropFields(fields)
	if len(fields) != 0 {
		w.ckwriters[TagField].Put(fields...)
		w.counter.FieldCount += int64(len(fields))
	} else {
		flushValues := w.cache.CheckOrFlushFields()
		if len(flushValues) > 0 {
			go w.WriteSmoothly(TagField, flushValues)
		}
		w.counter.FieldCount += int64(len(flushValues))
	}

	fieldValues = w.cache.CacheOrDropFieldValues(fieldValues)
	if len(fieldValues) != 0 {
		w.ckwriters[TagFieldValue].Put(fieldValues...)
		w.counter.FieldValueCount += int64(len(fieldValues))
	} else {
		flushValues := w.cache.CheckOrFlushFieldValues()
		if len(flushValues) > 0 {
			go w.WriteSmoothly(TagFieldValue, flushValues)
		}
		w.counter.FieldValueCount += int64(len(flushValues))
	}
	w.counter.FieldCacheHitCount += int64(fieldsCount - len(fields))
	w.counter.FieldValueCacheHitCount += int64(fieldValuesCount - len(fieldValues))
}

func (w *FlowTagWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	counter.FieldCacheCount = int64(len(w.cache.fieldCache))
	counter.FieldValueCacheCount = int64(len(w.cache.fieldValueCache))
	return counter
}
