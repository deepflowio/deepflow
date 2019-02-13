package store

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/op/go-logging"

	"github.com/influxdata/influxdb/models"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("influxdb_writer")

const (
	QUEUE_FETCH_MAX_SIZE       = 1024
	ESTIMATED_MAX_POINT_LENGTH = 1024
	DEFAULT_BATCH_SIZE         = 512 * 1024
	DEFAULT_FLUSH_TIMEOUT      = 5 // 单位 秒
	DEFAULT_QUEUE_SIZE         = 256 * 1024
	DEFAULT_QUEUE_NAME         = "influxdb_writer"
	INFLUXDB_PRECISION_S       = "s"
	UNIX_TIMESTAMP_TO_TIME     = (1969*365 + 1969/4 - 1969/100 + 1969/400) * 24 * 60 * 60
	TIME_BINARY_LEN            = 15
)

type InfluxdbItem interface {
	MarshalToBytes([]byte) int
	GetDBName() string
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

type PointCache struct {
	bp     client.BatchPoints
	buffer []byte
	offset int
}

type WriterInfo struct {
	httpClient client.Client
	writeTime  int64
	pointCache map[string]*PointCache
	counter    *Counter
	stats.Closable
}

type InfluxdbWriter struct {
	HttpClient       client.Client
	DataQueues       queue.FixedMultiQueue
	QueueCount       int
	QueueWriterInfos []*WriterInfo

	BatchSize    int
	FlushTimeout int64
	ExistDBs     map[string]bool
	addDBLock    sync.Mutex
}

func NewInfluxdbWriter(httpAddr string, queueCount int) (*InfluxdbWriter, error) {
	httpClient, err := client.NewHTTPClient(client.HTTPConfig{Addr: httpAddr})
	if err != nil {
		log.Error("create influxdb http client failed:", err)
		return nil, err
	}

	if _, _, err = httpClient.Ping(0); err != nil {
		log.Errorf("http connect to influxdb(%s) failed: %s", httpAddr, err)
	}

	queueWriterInfos, err := newWriterInfos(httpAddr, queueCount)
	if err != nil {
		log.Error("create queue writer infos failed:", err)
		return nil, err
	}

	return &InfluxdbWriter{
		HttpClient: httpClient,
		DataQueues: queue.NewOverwriteQueues(
			DEFAULT_QUEUE_NAME, queue.HashKey(queueCount), DEFAULT_QUEUE_SIZE,
			queue.OptionFlushIndicator(DEFAULT_FLUSH_TIMEOUT),
			queue.OptionRelease(func(p interface{}) { p.(InfluxdbItem).Release() })),
		QueueCount:       queueCount,
		QueueWriterInfos: queueWriterInfos,

		FlushTimeout: int64(DEFAULT_FLUSH_TIMEOUT),
		BatchSize:    DEFAULT_BATCH_SIZE,
		ExistDBs:     getCurrentDBs(httpClient),
	}, nil
}

func (w *InfluxdbWriter) SetQueueSize(size int) {
	w.DataQueues = queue.NewOverwriteQueues(DEFAULT_QUEUE_NAME, queue.HashKey(w.QueueCount), size, w.FlushTimeout,
		queue.OptionFlushIndicator(DEFAULT_FLUSH_TIMEOUT),
		queue.OptionRelease(func(p interface{}) { p.(InfluxdbItem).Release() }))
}

func (w *InfluxdbWriter) SetBatchSize(size int) {
	w.BatchSize = size
}

func (w *InfluxdbWriter) SetBatchTimeout(timeout int64) {
	w.FlushTimeout = timeout
}

// 高性能接口，需要用户实现InfluxdbItem接口
func (w *InfluxdbWriter) Put(queueID int, item InfluxdbItem) {
	w.DataQueues.Put(queue.HashKey(queueID), item)
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
	for n := 0; n < w.QueueCount; n++ {
		go w.queueProcess(n)
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

	for key, value := range p.tag {
		size += copy(buffer[offset+4+size:], ","+key+"="+value)
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

func (p *InfluxdbPoint) Release() {
}

func newWriterInfos(httpAddr string, count int) ([]*WriterInfo, error) {
	ws := make([]*WriterInfo, count)
	for i := 0; i < count; i++ {
		httpClient, err := client.NewHTTPClient(client.HTTPConfig{Addr: httpAddr})
		if err != nil {
			log.Error("create influxdb http client %d failed:", i, err)
			return nil, err
		}
		if _, _, err = httpClient.Ping(0); err != nil {
			log.Errorf("http %d connect to influxdb(%s) failed: %s", i, httpAddr, err)
		}
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

func newPointCache(db string, size int) *PointCache {
	bp, err := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  db,
		Precision: INFLUXDB_PRECISION_S,
	})
	if err != nil {
		panic(fmt.Sprintf("create BatchPoints for db %s failed: %s", db, err))
	}

	buffer := make([]byte, size+ESTIMATED_MAX_POINT_LENGTH)
	return &PointCache{
		bp:     bp,
		buffer: buffer,
	}
}

func (p *PointCache) Reset(db string) {
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  db,
		Precision: INFLUXDB_PRECISION_S,
	})
	p.bp = bp
	p.offset = 0
	return
}

func checkResponse(response *client.Response, err error) error {
	if err != nil {
		return err
	} else if err := response.Error(); err != nil {
		return err
	}
	return nil
}

func getCurrentDBs(httpClient client.Client) map[string]bool {
	dbs := make(map[string]bool)
	res, err := httpClient.Query(client.NewQuery("SHOW DATABASES", "", ""))
	if err := checkResponse(res, err); err != nil {
		log.Warning("Show databases failed, error info: %s", err)
	} else {
		databases := res.Results[0].Series[0].Values
		for _, col := range databases {
			if name, ok := col[0].(string); ok {
				dbs[name] = true
			}
		}
	}
	return dbs
}

func (w *InfluxdbWriter) queueProcess(queueID int) {
	stats.RegisterCountable("influxdb_writer", w.QueueWriterInfos[queueID], stats.OptionStatTags{"thread": strconv.Itoa(queueID)})
	defer w.QueueWriterInfos[queueID].Close()

	rawItems := make([]interface{}, QUEUE_FETCH_MAX_SIZE)
	for {
		n := w.DataQueues.Gets(queue.HashKey(queueID), rawItems)
		for i := 0; i < n; i++ {
			item := rawItems[i]
			if ii, ok := item.(InfluxdbItem); ok {
				w.writeCache(queueID, ii)
			} else if item == nil { // flush ticker
				if time.Now().Unix()-w.QueueWriterInfos[queueID].writeTime > w.FlushTimeout {
					w.flushWriteCache(queueID)
				}
			} else {
				log.Warning("get influxdb writer queue data type wrong")
			}
		}
	}
}

func (w *InfluxdbWriter) writeCache(queueID int, item InfluxdbItem) bool {
	pointCache := w.QueueWriterInfos[queueID].pointCache

	db := item.GetDBName()
	if _, ok := pointCache[db]; !ok {
		pointCache[db] = newPointCache(db, w.BatchSize)
	}
	buffer := pointCache[db].buffer
	offset := pointCache[db].offset
	size := item.MarshalToBytes(buffer[offset:])
	point, err := models.NewPointFromBytes(buffer[offset : offset+size])
	if err != nil {
		log.Errorf("new model point failed buffer size=%d, err:%s", size, err)
		return false
	}
	pointCache[db].bp.AddPoint(client.NewPointFrom(point))
	pointCache[db].offset += size

	item.Release()

	if pointCache[db].offset > w.BatchSize {
		w.writeInfluxdb(queueID, pointCache[db].bp)
		pointCache[db].Reset(db)
	}
	return true
}

func (w *InfluxdbWriter) flushWriteCache(queueID int) {
	pointCache := w.QueueWriterInfos[queueID].pointCache
	for db, pc := range pointCache {
		if len(pc.bp.Points()) <= 0 {
			continue
		}
		log.Debugf("flush %d points to %s", len(pc.bp.Points()), db)
		w.writeInfluxdb(queueID, pc.bp)
		pc.Reset(db)
	}
}

func createDB(httpClient client.Client, db string) bool {
	log.Infof("database %s no exists, create database now.", db)
	res, err := httpClient.Query(client.NewQuery(
		fmt.Sprintf("CREATE DATABASE %s", db), "", ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("Create database %s failed, error info: %s", db, err)
		return false
	}
	return true
}

func (w *InfluxdbWriter) writeInfluxdb(queueID int, bp client.BatchPoints) bool {
	w.QueueWriterInfos[queueID].writeTime = time.Now().Unix()
	httpClient := w.QueueWriterInfos[queueID].httpClient
	db := bp.Database()
	if _, ok := w.ExistDBs[db]; !ok {
		if !createDB(httpClient, db) {
			w.QueueWriterInfos[queueID].counter.WriteFailedCount += int64(len(bp.Points()))
			return false
		}
		w.addDBLock.Lock()
		w.ExistDBs[db] = true
		w.addDBLock.Unlock()
	}

	if err := httpClient.Write(bp); err != nil {
		w.QueueWriterInfos[queueID].counter.WriteFailedCount += int64(len(bp.Points()))
		log.Errorf("db(%s) write batch point failed: %s", db, err)
		return false
	}
	w.QueueWriterInfos[queueID].counter.WriteSuccessCount += int64(len(bp.Points()))

	return true
}
