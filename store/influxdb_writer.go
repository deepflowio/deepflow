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
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("influxdb_writer")

const (
	QUEUE_FETCH_MAX_SIZE   = 1024
	DEFAULT_BATCH_SIZE     = 512 * 1024
	DEFAULT_FLUSH_TIMEOUT  = 5 // 单位 秒
	DEFAULT_QUEUE_SIZE     = 256 * 1024
	INFLUXDB_PRECISION_S   = "s"
	UNIX_TIMESTAMP_TO_TIME = (1969*365 + 1969/4 - 1969/100 + 1969/400) * 24 * 60 * 60
	TIME_BINARY_LEN        = 15
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
	WriteSuccessCount1 int64 `statsd:"write-success-count1"`
	WriteFailedCount1  int64 `statsd:"write-failed-count1"`
	WriteSuccessCount2 int64 `statsd:"write-success-count2"`
	WriteFailedCount2  int64 `statsd:"write-failed-count2"`
}

type PointCache struct {
	bp     client.BatchPoints
	buffer []byte
	offset int
}

type WriterInfo struct {
	httpClients []client.Client
	writeTime   int64
	pointCache  map[string]*PointCache
	counter     *Counter
	stats.Closable
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
	DBCreateCtls     []DBCreateCtl
	DataQueues       queue.FixedMultiQueue
	Name             string
	QueueCount       int
	QueueWriterInfos []*WriterInfo

	BatchSize    int
	FlushTimeout int64
	RP           RetentionPolicy
	exit         bool
}

func NewInfluxdbWriter(httpAddrs []string, name string, queueCount int) (*InfluxdbWriter, error) {
	DBCreateCtls := make([]DBCreateCtl, 0)
	for _, httpAddr := range httpAddrs {
		httpClient, err := client.NewHTTPClient(client.HTTPConfig{Addr: httpAddr})
		if err != nil {
			log.Error("create influxdb http client failed:", err)
			return nil, err
		}

		if _, _, err = httpClient.Ping(0); err != nil {
			log.Errorf("http connect to influxdb(%s) failed: %s", httpAddr, err)
		}
		dbCtl := DBCreateCtl{
			HttpClient: httpClient,
			ExistDBs:   make(map[string]bool),
		}
		DBCreateCtls = append(DBCreateCtls, dbCtl)
	}

	queueWriterInfos, err := newWriterInfos(httpAddrs, queueCount)
	if err != nil {
		log.Error("create queue writer infos failed:", err)
		return nil, err
	}

	return &InfluxdbWriter{
		DataQueues: queue.NewOverwriteQueues(
			name, queue.HashKey(queueCount), DEFAULT_QUEUE_SIZE,
			queue.OptionFlushIndicator(time.Second),
			queue.OptionRelease(func(p interface{}) { p.(InfluxdbItem).Release() })),
		QueueCount:       queueCount,
		QueueWriterInfos: queueWriterInfos,

		FlushTimeout: int64(DEFAULT_FLUSH_TIMEOUT),
		BatchSize:    DEFAULT_BATCH_SIZE,
		Name:         name,
		DBCreateCtls: DBCreateCtls,
	}, nil
}

func (w *InfluxdbWriter) SetQueueSize(size int) {
	w.DataQueues = queue.NewOverwriteQueues(w.Name, queue.HashKey(w.QueueCount), size,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(InfluxdbItem).Release() }))
}

func (w *InfluxdbWriter) SetBatchSize(size int) {
	w.BatchSize = size
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

func newWriterInfos(httpAddrs []string, count int) ([]*WriterInfo, error) {
	ws := make([]*WriterInfo, count)
	for i := 0; i < count; i++ {
		httpClients := make([]client.Client, 0)
		for _, httpAddr := range httpAddrs {
			httpClient, err := client.NewHTTPClient(client.HTTPConfig{Addr: httpAddr})
			if err != nil {
				log.Error("create influxdb http client %d failed:", i, err)
				return nil, err
			}
			if _, _, err = httpClient.Ping(0); err != nil {
				log.Errorf("http %d connect to influxdb(%s) failed: %s", i, httpAddr, err)
			}
			httpClients = append(httpClients, httpClient)
			log.Infof("new influxdb http client %s", httpAddr)
		}
		ws[i] = &WriterInfo{
			httpClients: httpClients,
			writeTime:   time.Now().Unix(),
			pointCache:  make(map[string]*PointCache),
			counter:     &Counter{},
		}
	}
	return ws, nil
}

func (i *WriterInfo) GetCounter() interface{} {
	var counter *Counter
	counter, i.counter = i.counter, &Counter{}

	return counter
}

func newPointCache(db, rp string, size int) *PointCache {
	bp, err := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        db,
		Precision:       INFLUXDB_PRECISION_S,
		RetentionPolicy: rp,
	})
	if err != nil {
		panic(fmt.Sprintf("create BatchPoints for db %s failed: %s", db, err))
	}

	buffer := make([]byte, size+app.MAX_DOC_STRING_LENGTH)
	return &PointCache{
		bp:     bp,
		buffer: buffer,
	}
}

func (p *PointCache) Reset(db, rp string) {
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        db,
		Precision:       INFLUXDB_PRECISION_S,
		RetentionPolicy: rp,
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
	stats.RegisterCountable(w.Name, w.QueueWriterInfos[queueID], stats.OptionStatTags{"thread": strconv.Itoa(queueID)})
	defer w.QueueWriterInfos[queueID].Close()

	rawItems := make([]interface{}, QUEUE_FETCH_MAX_SIZE)
	for !w.exit {
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
		pointCache[db] = newPointCache(db, w.RP.name, w.BatchSize)
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
		pointCache[db].Reset(db, w.RP.name)
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
		pc.Reset(db, w.RP.name)
	}
}

func createRetentionPolicy(httpClient client.Client, dbName, rpName, duration, shardDuration string, defaultFlag bool) bool {
	setDefault := ""
	if defaultFlag {
		setDefault = "default"
	}
	cmd := fmt.Sprintf("CREATE RETENTION POLICY %s ON %s DURATION %s REPLICATION 1 SHARD DURATION %s %s",
		rpName, dbName, duration, shardDuration, setDefault)

	res, err := httpClient.Query(client.NewQuery(
		cmd, dbName, ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("DB(%s) create retention policy(%s) failed, error info: %s", dbName, rpName, err)
		return false
	}

	log.Infof("DB(%s) create retention policy(%s)", dbName, cmd)
	return true
}

func retentionPolicyExists(httpClient client.Client, db, rp string) bool {
	// Validate if specified retention policy exists
	response, err := httpClient.Query(client.Query{Command: fmt.Sprintf("SHOW RETENTION POLICIES ON %q", db)})
	if err := checkResponse(response, err); err != nil {
		log.Warningf("DB(%s) check retention policy(%s) failed: %s", db, rp, err)
		return false
	}

	for _, result := range response.Results {
		for _, row := range result.Series {
			for _, values := range row.Values {
				for k, v := range values {
					if k != 0 {
						continue
					}
					if v == rp {
						return true
					}
				}
			}
		}
	}
	log.Warningf("DB(%s) retention policy(%s) not exist", db, rp)

	return false
}

func alterRetentionPolicy(httpClient client.Client, dbName, rpName, duration, shardDuration string, defaultFlag bool) bool {
	setDefault := ""
	if defaultFlag {
		setDefault = "default"
	}
	cmd := fmt.Sprintf("ALTER RETENTION POLICY %s ON %s DURATION %s SHARD DURATION %s %s",
		rpName, dbName, duration, shardDuration, setDefault)

	res, err := httpClient.Query(client.NewQuery(
		cmd, dbName, ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("DB(%s) alter retention policy(%s) failed, error info: %s", dbName, rpName, err)
		return false
	}

	log.Infof("DB(%s) alter retention policy(%s)", dbName, cmd)
	return true
}

func (w *InfluxdbWriter) createDB(httpClient client.Client, db string) bool {
	log.Infof("database %s no exists, create database now.", db)
	res, err := httpClient.Query(client.NewQuery(
		fmt.Sprintf("CREATE DATABASE %s", db), "", ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("Create database %s failed, error info: %s", db, err)
		return false
	}

	if w.RP.name != "" {
		if retentionPolicyExists(httpClient, db, w.RP.name) {
			return alterRetentionPolicy(httpClient, db, w.RP.name, w.RP.duration, w.RP.shardDuration, w.RP.defaultFlag)
		} else {
			return createRetentionPolicy(httpClient, db, w.RP.name, w.RP.duration, w.RP.shardDuration, w.RP.defaultFlag)
		}
	}

	return true
}

func (w *InfluxdbWriter) writeInfluxdb(queueID int, bp client.BatchPoints) bool {
	w.QueueWriterInfos[queueID].writeTime = time.Now().Unix()
	ret := true
	httpClients := w.QueueWriterInfos[queueID].httpClients
	db := bp.Database()

	for i, httpClient := range httpClients {
		var writeSuccCount, writeFailedCount *int64
		if i == 0 {
			writeFailedCount = &w.QueueWriterInfos[queueID].counter.WriteFailedCount1
			writeSuccCount = &w.QueueWriterInfos[queueID].counter.WriteSuccessCount1
		} else {
			writeFailedCount = &w.QueueWriterInfos[queueID].counter.WriteFailedCount2
			writeSuccCount = &w.QueueWriterInfos[queueID].counter.WriteSuccessCount2
		}

		w.DBCreateCtls[i].RLock()
		_, ok := w.DBCreateCtls[i].ExistDBs[db]
		w.DBCreateCtls[i].RUnlock()

		if !ok {
			if !w.createDB(httpClient, db) {
				*writeFailedCount += int64(len(bp.Points()))
				ret = false
				continue
			}
			w.DBCreateCtls[i].Lock()
			w.DBCreateCtls[i].ExistDBs[db] = true
			w.DBCreateCtls[i].Unlock()
		}

		if err := httpClient.Write(bp); err != nil {
			*writeFailedCount += int64(len(bp.Points()))
			log.Errorf("httpclient index(%d) db(%s) write batch point failed: %s", i, db, err)
			ret = false
			continue
		}
		*writeSuccCount += int64(len(bp.Points()))
	}

	return ret
}

func (w *InfluxdbWriter) Close() {
	w.exit = true

	for _, dbCtl := range w.DBCreateCtls {
		dbCtl.HttpClient.Close()
	}

	for _, writeInfo := range w.QueueWriterInfos {
		for _, httpClient := range writeInfo.httpClients {
			httpClient.Close()
		}
	}

	log.Info("Stopped influx writer")
}
