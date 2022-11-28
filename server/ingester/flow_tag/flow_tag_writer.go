package flow_tag

import (
	"fmt"
	"sync"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/stats"
	"github.com/deepflowys/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

const (
	FLOW_TAG_CACHE_FLUSH_TIMEOUT = 10 * 60 // s
	FLOW_TAG_CACHE_INIT_SIZE     = 1 << 14
	FLOW_TAG_CACHE_MAX_SIZE      = 1 << 18
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
	ckdbAddr     string
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
}

func NewFlowTagCache() *FlowTagCache {
	return &FlowTagCache{
		fieldCache:              make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE),
		fieldValueCache:         make(map[FlowTagInfo]*FlowTag, FLOW_TAG_CACHE_INIT_SIZE),
		lastFieldFlushTime:      time.Now().Unix(),
		lastFieldValueFlushTime: time.Now().Unix(),
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
	if time.Now().Unix()-c.lastFieldFlushTime < FLOW_TAG_CACHE_FLUSH_TIMEOUT &&
		len(c.fieldCache) < FLOW_TAG_CACHE_MAX_SIZE {
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
	if time.Now().Unix()-c.lastFieldValueFlushTime < FLOW_TAG_CACHE_FLUSH_TIMEOUT &&
		len(c.fieldValueCache) < FLOW_TAG_CACHE_MAX_SIZE {
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
		ckdbAddr:     config.CKDB.ActualAddr,
		ckdbUsername: config.CKDBAuth.Username,
		ckdbPassword: config.CKDBAuth.Password,
		writerConfig: writerConfig,

		cache:   NewFlowTagCache(),
		counter: &Counter{},
	}
	t := FlowTag{}
	var err error
	for _, tagType := range []TagType{TagField, TagFieldValue} {
		t.TableName = fmt.Sprintf("%s_%s", srcDB, tagType.String())
		t.hasFieldValue = false
		if tagType == TagFieldValue {
			t.hasFieldValue = true
		}
		w.ckwriters[tagType], err = ckwriter.NewCKWriter(w.ckdbAddr, "", w.ckdbUsername, w.ckdbPassword,
			fmt.Sprintf("%s_%s", name, t.TableName), t.GenCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, ttl, partition), false, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
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

func (w *FlowTagWriter) WriteFieldsAndFieldValues(fields, fieldValues []interface{}) {
	fieldsCount, fieldValuesCount := len(fields), len(fieldValues)
	fields = w.cache.CacheOrDropFields(fields)
	if len(fields) != 0 {
		if w.counter.FieldCount == 0 {
			flushValues := w.cache.CheckOrFlushFields()
			if len(flushValues) > 0 {
				w.ckwriters[TagField].Put(flushValues...)
			}
			w.counter.FieldCount += int64(len(flushValues))
		}
		w.ckwriters[TagField].Put(fields...)
		w.counter.FieldCount += int64(len(fields))
	}

	fieldValues = w.cache.CacheOrDropFieldValues(fieldValues)
	if len(fieldValues) != 0 {
		if w.counter.FieldValueCount == 0 {
			flushValues := w.cache.CheckOrFlushFieldValues()
			if len(flushValues) > 0 {
				w.ckwriters[TagFieldValue].Put(flushValues...)
			}
			w.counter.FieldValueCount += int64(len(flushValues))
		}
		w.ckwriters[TagFieldValue].Put(fieldValues...)
		w.counter.FieldValueCount += int64(len(fieldValues))
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
