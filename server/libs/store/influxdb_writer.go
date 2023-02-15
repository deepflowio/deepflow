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

package store

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"

	// 需要从github.com获取新的写入接口，然后在Makefile中拷贝到vendor/github.com/influxdata/influxdb/client/v2
	// _ "github.com/platform/influxdb/client/v2"

	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("store")

const (
	QUEUE_FETCH_MAX_SIZE   = 1024
	DEFAULT_BATCH_SIZE     = 512 * 1024
	DEFAULT_FLUSH_TIMEOUT  = 5 // 单位 秒
	DEFAULT_QUEUE_SIZE     = 256 * 1024
	INFLUXDB_PRECISION_S   = "s"
	UNIX_TIMESTAMP_TO_TIME = (1969*365 + 1969/4 - 1969/100 + 1969/400) * 24 * 60 * 60
	TIME_BINARY_LEN        = 15
	MAX_ERR_MSG_LEN        = 512
)

type InfluxdbItem interface {
	MarshalToBytes([]byte) int
	GetDBName() string
	GetMeasurement() string
	GetTimestamp() uint32
	Release()
}

type InfluxdbPoint struct {
	db          string
	measurement string
	tag         map[string]string
	field       map[string]int64
	timestamp   uint32 // 秒
}

type Counter struct {
	WriteSuccessCount int64 `statsd:"write-success-count"`
	WriteFailedCount  int64 `statsd:"write-failed-count"`
}

type Confidence struct {
	db          string
	measurement string
	shardID     string
	timestamp   int64 // time.Duration
	status      RepairStatus
}

type PointCache struct {
	buffer      []byte
	offset      int
	confidences map[Confidence]uint8

	bp client.BatchPoints

	database string
	rp       string
	count    int
}

var bufferPool = pool.NewLockFreePool(func() interface{} {
	return make([]byte, DEFAULT_BATCH_SIZE+zerodoc.MAX_STRING_LENGTH)
},
	pool.OptionPoolSizePerCPU(8),
	pool.OptionInitFullPoolSize(8))

func acquireBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// 只能realease acquireBuffer出来的 slice
func releaseBuffer(b []byte) {
	bufferPool.Put(b)
}

var pointCachePool = pool.NewLockFreePool(func() interface{} {
	return &PointCache{}
})

func acquirePointCache() *PointCache {
	return pointCachePool.Get().(*PointCache)
}

func releasePointCache(p *PointCache) {
	if p == nil {
		return
	}
	if p.buffer != nil {
		releaseBuffer(p.buffer)
	}
	*p = PointCache{}
	pointCachePool.Put(p)
}

type WriterInfo struct {
	httpClient  client.Client
	isConnected bool
	writeTime   int64
	pointCache  map[string]*PointCache
	counter     *Counter
	utils.Closable
}

type DBCreateCtl struct {
	HttpClient client.Client
	ExistDBs   map[string]bool
	sync.RWMutex
}

type RetentionPolicy struct {
	name          string
	duration      string
	shardDuration string
	defaultFlag   bool
}

type InfluxdbWriter struct {
	ReplicaEnabled bool
	DataQueues     queue.FixedMultiQueue
	ReplicaQueues  queue.FixedMultiQueue
	WriteDirect    bool

	Name                    string
	ShardID                 string
	QueueCount              int
	QueueWriterInfosPrimary []*WriterInfo
	QueueWriterInfosReplica []*WriterInfo

	DBCreateCtlPrimary DBCreateCtl
	DBCreateCtlReplica DBCreateCtl

	PrimaryClient client.Client
	BatchSize     int
	FlushTimeout  int64
	RP            RetentionPolicy
	wg            sync.WaitGroup
	exit          bool
}

func NewInfluxdbWriter(addrPrimary, addrReplica, httpUsername, httpPassword, name, shardID string, queueCount, queueSize int) (*InfluxdbWriter, error) {
	w := &InfluxdbWriter{
		Name:         name,
		QueueCount:   queueCount,
		BatchSize:    DEFAULT_BATCH_SIZE,
		FlushTimeout: int64(DEFAULT_FLUSH_TIMEOUT),
		ShardID:      shardID,
		WriteDirect:  true,
	}

	primaryHTTPConfig := client.HTTPConfig{Addr: addrPrimary, Username: httpUsername, Password: httpPassword}
	httpClient, err := client.NewHTTPClient(primaryHTTPConfig)
	if err != nil {
		log.Error("create influxdb http client failed:", err)
		return nil, err
	}

	if _, _, err = httpClient.Ping(0); err != nil {
		log.Errorf("http connect to influxdb(%s) failed: %s", addrPrimary, err)
	}
	w.PrimaryClient = httpClient
	w.DBCreateCtlPrimary.HttpClient = httpClient
	w.DBCreateCtlPrimary.ExistDBs = make(map[string]bool)
	w.DataQueues = queue.NewOverwriteQueues(
		name, queue.HashKey(queueCount), queueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(InfluxdbItem).Release() }))
	w.QueueWriterInfosPrimary, err = newWriterInfos(primaryHTTPConfig, queueCount)
	if err != nil {
		log.Error("create queue writer infos failed:", err)
		return nil, err
	}

	if addrReplica != "" {
		w.ReplicaEnabled = true
		replicaHTTPConfig := client.HTTPConfig{Addr: addrReplica, Username: httpUsername, Password: httpPassword}
		httpClient, err := client.NewHTTPClient(replicaHTTPConfig)
		if err != nil {
			log.Error("create replica influxdb http client failed:", err)
			return nil, err
		}

		if _, _, err = httpClient.Ping(0); err != nil {
			log.Errorf("http connect to influxdb(%s) failed: %s", addrReplica, err)
		}
		w.DBCreateCtlReplica.HttpClient = httpClient
		w.DBCreateCtlReplica.ExistDBs = make(map[string]bool)

		w.QueueWriterInfosReplica, err = newWriterInfos(replicaHTTPConfig, queueCount)
		if err != nil {
			log.Error("create queue writer infos failed:", err)
			return nil, err
		}

		w.ReplicaQueues = queue.NewOverwriteQueues(
			name+"_replica", queue.HashKey(queueCount), 1024, // FIXME: New时带入queueSize
			queue.OptionFlushIndicator(time.Second),
			queue.OptionRelease(func(p interface{}) { releasePointCache(p.(*PointCache)) }))
	}

	log.Infof("NewInfluxdbWriter shardID(%s) threads(%d) primary(%s) replica(%s) direct(%v)", shardID, queueCount, addrPrimary, addrReplica, w.WriteDirect)
	return w, nil
}

func (w *InfluxdbWriter) SetBatchSize(size int) {
	if size <= DEFAULT_BATCH_SIZE {
		w.BatchSize = size
	} else {
		log.Warningf("batch size must small than %d", DEFAULT_BATCH_SIZE)
	}
}

func (w *InfluxdbWriter) SetWriteDirect(enabled bool) {
	w.WriteDirect = enabled
}

func (w *InfluxdbWriter) SetBatchTimeout(timeout int64) {
	w.FlushTimeout = timeout
}

func (w *InfluxdbWriter) SetRetentionPolicy(rp, duration, shardDuration string, defaultFlag bool) {
	w.RP.name = rp
	w.RP.duration = duration
	w.RP.shardDuration = shardDuration
	w.RP.defaultFlag = defaultFlag
}

// 高性能接口，需要用户实现InfluxdbItem接口
func (w *InfluxdbWriter) Put(queueID int, item ...interface{}) {
	w.DataQueues.Put(queue.HashKey(queueID), item...)
}

// 普通接口，性能较差，易用
func (w *InfluxdbWriter) PutPoint(queueID int, db, measurement string, tag map[string]string, field map[string]int64, timestamp uint32) {
	w.DataQueues.Put(queue.HashKey(queueID), &InfluxdbPoint{
		db:          db,
		measurement: measurement,
		tag:         tag,
		field:       field,
		timestamp:   timestamp,
	})
}

func (w *InfluxdbWriter) Run() {
	w.createDB(w.PrimaryClient, CONFIDENCE_DB)
	for n := 0; n < w.QueueCount; n++ {
		go w.queueProcess(n)
		if w.ReplicaEnabled {
			go w.queueProcessReplica(n)
		}
	}
}

func MarshalTimestampTo(ts uint32, buffer []byte) int {
	// golang time binary format:
	//     byte 0: version (1)
	//     bytes 1-8: seconds (big-endian)
	//     bytes 9-12: nanoseconds (big-endian)
	//     bytes 13-14: zone offset in minutes (-1 for UTC)
	realTime := uint64(ts) + UNIX_TIMESTAMP_TO_TIME
	buffer[0] = 1
	binary.BigEndian.PutUint64(buffer[1:], realTime)
	binary.BigEndian.PutUint32(buffer[9:], 0)
	buffer[13] = ^byte(0)
	buffer[14] = ^byte(0)
	return TIME_BINARY_LEN
}

func (p *InfluxdbPoint) MarshalToBytes(buffer []byte) int {
	offset := 0
	size := copy(buffer[offset+4:], p.measurement)

	keys := make([]string, 0, len(p.tag))
	for key, _ := range p.tag {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		size += copy(buffer[offset+4+size:], ","+key+"="+p.tag[key])
	}

	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	size = 0
	for key, value := range p.field {
		if size != 0 {
			size += copy(buffer[offset+4+size:], ",")
		}
		size += copy(buffer[offset+4+size:], key+"="+strconv.FormatInt(value, 10)+"i")
	}

	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	offset += MarshalTimestampTo(p.timestamp, buffer[offset:])

	return offset
}

func (p *InfluxdbPoint) GetDBName() string {
	return p.db
}

func (p *InfluxdbPoint) GetMeasurement() string {
	return p.measurement
}

func (p *InfluxdbPoint) GetTimestamp() uint32 {
	return p.timestamp
}

func (p *InfluxdbPoint) Release() {
}

func newWriterInfos(httpConfig client.HTTPConfig, count int) ([]*WriterInfo, error) {
	ws := make([]*WriterInfo, count)
	for i := 0; i < count; i++ {
		httpClient, err := client.NewHTTPClient(httpConfig)
		if err != nil {
			log.Error("create influxdb http client %d failed: ", i, err)
			return nil, err
		}
		if _, _, err = httpClient.Ping(0); err != nil {
			log.Errorf("http %d connect to influxdb(%s) failed: %s", i, httpConfig.Addr, err)
		}
		log.Infof("new influxdb http client %d: %s", i, httpConfig.Addr)
		ws[i] = &WriterInfo{
			httpClient: httpClient,
			writeTime:  time.Now().Unix(),
			pointCache: make(map[string]*PointCache),
			counter:    &Counter{},
		}
	}
	return ws, nil
}

func (i *WriterInfo) GetCounter() interface{} {
	var counter *Counter
	counter, i.counter = i.counter, &Counter{}

	return counter
}

func (i *WriterInfo) Close() {
	if i.httpClient != nil {
		i.httpClient.Close()
		i.httpClient = nil
	}
	i.Closable.Close()
}

func (w *InfluxdbWriter) newPointCache(db, rp string) *PointCache {
	pc := acquirePointCache()
	if w.WriteDirect {
		pc.database = db
		pc.rp = rp
	} else {
		bp, err := client.NewBatchPoints(client.BatchPointsConfig{
			Database:        db,
			Precision:       INFLUXDB_PRECISION_S,
			RetentionPolicy: rp,
		})
		if err != nil {
			panic(fmt.Sprintf("create BatchPoints for db %s failed: %s", db, err))
		}
		pc.bp = bp
	}
	pc.confidences = make(map[Confidence]uint8)
	pc.buffer = acquireBuffer()
	return pc
}

func (w *InfluxdbWriter) queueProcess(queueID int) {
	stats.RegisterCountable(w.Name, w.QueueWriterInfosPrimary[queueID], stats.OptionStatTags{"thread": strconv.Itoa(queueID)})
	defer w.QueueWriterInfosPrimary[queueID].Close()
	defer w.wg.Done()
	w.wg.Add(1)

	rawItems := make([]interface{}, QUEUE_FETCH_MAX_SIZE)
	for !w.exit {
		n := w.DataQueues.Gets(queue.HashKey(queueID), rawItems)
		for i := 0; i < n; i++ {
			item := rawItems[i]
			if ii, ok := item.(InfluxdbItem); ok {
				w.writeCache(queueID, ii)
			} else if item == nil { // flush ticker
				if time.Now().Unix()-w.QueueWriterInfosPrimary[queueID].writeTime > w.FlushTimeout {
					w.flushWriteCache(queueID)
				}
			} else {
				log.Warning("get influxdb writer queue data type wrong")
			}
		}
	}
}

func (w *InfluxdbWriter) writeCache(queueID int, item InfluxdbItem) bool {
	pointCache := w.QueueWriterInfosPrimary[queueID].pointCache

	db := item.GetDBName()
	if _, ok := pointCache[db]; !ok {
		pointCache[db] = w.newPointCache(db, w.RP.name)
	}
	buffer := pointCache[db].buffer
	offset := pointCache[db].offset

	size := item.MarshalToBytes(buffer[offset:])
	if !w.WriteDirect {
		point, err := models.NewPointFromBytes(buffer[offset : offset+size])
		if err != nil {
			log.Errorf("new model point failed buffer size=%d, err:%s", size, err)
			return false
		}
		pointCache[db].bp.AddPoint(client.NewPointFrom(point))
	}
	pointCache[db].confidences[Confidence{
		db:          db,
		measurement: item.GetMeasurement(),
		timestamp:   int64(item.GetTimestamp()),
	}] = 0

	pointCache[db].offset += size
	pointCache[db].count++

	item.Release()

	if pointCache[db].offset > w.BatchSize {
		w.writePrimary(queueID, pointCache[db])
		pointCache[db] = w.newPointCache(db, w.RP.name)
	}
	return true
}

func (w *InfluxdbWriter) flushWriteCache(queueID int) {
	pointCache := w.QueueWriterInfosPrimary[queueID].pointCache
	for db, pc := range pointCache {
		if pc.count <= 0 {
			continue
		}
		log.Debugf("flush %d bytes to %s", pc.count, db)

		w.writePrimary(queueID, pc)
		pointCache[db] = w.newPointCache(db, w.RP.name)
	}
}

func (w *InfluxdbWriter) createDB(httpClient client.Client, db string) error {
	log.Infof("database %s no exists, create database now.", db)
	res, err := httpClient.Query(client.NewQuery(
		fmt.Sprintf("CREATE DATABASE %s", db), "", ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("Create database %s failed, error info: %s", db, err)
		return err
	}

	if w.RP.name != "" {
		if retentionPolicyExists(httpClient, db, w.RP.name) {
			return nil
		} else {
			return createRetentionPolicy(httpClient, db, &w.RP)
		}
	}

	return nil
}

func (w *InfluxdbWriter) writeInfluxdb(writerInfo *WriterInfo, dbCreateCtl *DBCreateCtl, pc *PointCache) error {
	var pointsCount int64
	var db string
	var err error

	writerInfo.writeTime = time.Now().Unix()

	if w.WriteDirect {
		db = pc.database
		pointsCount = int64(pc.count)
	} else {
		db = pc.bp.Database()
		pointsCount = int64(len(pc.bp.Points()))
	}

	writeFailedCount := &writerInfo.counter.WriteFailedCount
	writeSuccCount := &writerInfo.counter.WriteSuccessCount

	dbCreateCtl.RLock()
	_, ok := dbCreateCtl.ExistDBs[db]
	dbCreateCtl.RUnlock()

	if !ok {
		if err := w.createDB(writerInfo.httpClient, db); err != nil {
			*writeFailedCount += pointsCount
			return fmt.Errorf("create database(%s) failed: %s", db, err)
		}
		dbCreateCtl.Lock()
		dbCreateCtl.ExistDBs[db] = true
		dbCreateCtl.Unlock()
	}

	if w.WriteDirect {
		// err = writerInfo.httpClient.WriteDirect(db, pc.rp, pc.buffer[:pc.offset])
	} else {
		err = writerInfo.httpClient.Write(pc.bp)
	}
	if err != nil {
		*writeFailedCount += pointsCount
		errMsg := err.Error()
		if len(errMsg) < MAX_ERR_MSG_LEN {
			return fmt.Errorf("httpclient write db(%s) batch points(%d) failed: %s", db, pointsCount, errMsg)
		}
		return fmt.Errorf("httpclient write db(%s) batch points(%d) failed: %s ... %s", db, pointsCount, errMsg[:MAX_ERR_MSG_LEN], errMsg[len(errMsg)-MAX_ERR_MSG_LEN:])
	}

	*writeSuccCount += pointsCount
	return nil
}

func (w *InfluxdbWriter) writePrimary(queueID int, pc *PointCache) bool {
	writerInfo := w.QueueWriterInfosPrimary[queueID]

	writeFailedCount := writerInfo.counter.WriteFailedCount
	if err := w.writeInfluxdb(writerInfo, &w.DBCreateCtlPrimary, pc); err != nil {
		// 防止写失败不断打印日志
		if writeFailedCount == 0 {
			log.Errorf("write primary failed. %s", err)
		}
		w.writeConfidence(pc, PRIMARY_FAILED)
		releasePointCache(pc)
		return false
	}

	if w.ReplicaEnabled {
		w.ReplicaQueues.Put(queue.HashKey(queueID), pc)
		return true
	}
	releasePointCache(pc)
	return true
}

func (w *InfluxdbWriter) writeReplica(queueID int, pc *PointCache) bool {
	writerInfo := w.QueueWriterInfosReplica[queueID]
	if !writerInfo.isConnected {
		w.writeConfidence(pc, REPLICA_DISCONNECT)
		releasePointCache(pc)
		return false
	}

	writeFailedCount := writerInfo.counter.WriteFailedCount
	if err := w.writeInfluxdb(writerInfo, &w.DBCreateCtlReplica, pc); err != nil {
		// 防止写失败不断打印日志
		if writeFailedCount == 0 {
			log.Errorf("write replica failed. %s", err)
		}
		if strings.Contains(err.Error(), "max-series-per-database limit exceeded") {
			w.writeConfidence(pc, SYNC_FAILED_SERIES_EXCEED)
		} else {
			w.writeConfidence(pc, SYNC_FAILED_1)
		}
		releasePointCache(pc)
		return false
	}

	releasePointCache(pc)
	return true
}

func (w *InfluxdbWriter) queueProcessReplica(queueID int) {
	writerInfo := w.QueueWriterInfosReplica[queueID]
	stats.RegisterCountable(w.Name+"_replica", writerInfo, stats.OptionStatTags{"thread": strconv.Itoa(queueID)})
	defer writerInfo.Close()
	defer w.wg.Done()
	w.wg.Add(1)

	for !w.exit {
		item := w.ReplicaQueues.Get(queue.HashKey(queueID))
		if item == nil { // flush ticker
			if _, _, err := writerInfo.httpClient.Ping(0); err != nil {
				writerInfo.isConnected = false
			} else {
				writerInfo.isConnected = true
			}
			continue
		} else if pc, ok := item.(*PointCache); ok {
			w.writeReplica(queueID, pc)
		} else {
			log.Warning("get influxdb replica writer queue data type wrong (%T)", item)
		}
	}
}

func (w *InfluxdbWriter) writeConfidence(pc *PointCache, status RepairStatus) {
	confidenceBP, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        CONFIDENCE_DB,
		Precision:       INFLUXDB_PRECISION_S,
		RetentionPolicy: w.RP.name,
	})

	tags := make(map[string]string)
	fields := make(map[string]interface{})
	for confidence, _ := range pc.confidences {
		tags[TAG_DB] = confidence.db
		tags[TAG_MEASUREMENT] = confidence.measurement
		tags[TAG_ID] = w.ShardID
		fields[FIELD_STATUS] = int64(status)

		measurement := CONFIDENCE_MEASUREMENT
		if !isStatusNeedRepair(status) {
			measurement = CONFIDENCE_MEASUREMENT_SYNCED
		}

		if pt, err := client.NewPoint(measurement, tags, fields, time.Unix(confidence.timestamp, 0)); err == nil {
			confidenceBP.AddPoint(pt)
		} else {
			log.Warning("new NewPoint failed:", err)
		}
	}

	if len(confidenceBP.Points()) > 0 {
		if err := w.PrimaryClient.Write(confidenceBP); err != nil {
			// 写主失败, 不打印写confidence失败日志
			if status != PRIMARY_FAILED {
				log.Errorf("httpclient  db(%s) write batch point failed: %s", CONFIDENCE_DB, err)
			}
		}
	}
}

func (w *InfluxdbWriter) Close() {
	w.exit = true
	w.wg.Wait()

	if w.DBCreateCtlReplica.HttpClient != nil {
		w.DBCreateCtlReplica.HttpClient.Close()
	}
	if w.DBCreateCtlPrimary.HttpClient != nil {
		w.DBCreateCtlPrimary.HttpClient.Close()
	}

	log.Info("Stopped influx writer")
}
