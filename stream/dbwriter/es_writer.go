package dbwriter

import (
	"context"
	"fmt"
	"time"

	"github.com/olivere/elastic"
	logging "github.com/op/go-logging"

	"math/rand"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet/stream/common"
)

var log = logging.MustGetLogger("es_writer")

const (
	BULK_SIZE               = 8192
	MAX_BULK_WRITE_INTERVAL = 10
	QUEUE_FETCH_SIZE        = 100
)

type Counter struct {
	MaxExecTime     int64 `statsd:"max-exec-time"`
	AvgExecTime     int64 `statsd:"avg-exec-time"`
	TotalWriteCount int64 `statsd:"total-write-count"`
}

type ESItem interface {
	EndTime() time.Duration
	Release()
}

type ESWriter struct {
	utils.Closable

	AppName           string
	DataType          string
	Mapping           string
	Addresses         []string
	User, Password    string
	RetentionPolicy   common.RetentionPolicy
	OpLoadFactor      int
	RawFlowEsTemplate string
	ESQueue           queue.QueueReader
	client            *elastic.Client
	lastIndexTime     time.Duration
	bulkFlow          []ESItem
	lastBulkTime      time.Duration
	maxExecTime       time.Duration
	avgExecTime       time.Duration
	totalWriteCount   int64
}

// Open es初始化连接
func (esWriter *ESWriter) Open(statOptions ...stats.Option) {
	for esWriter.client == nil {
		time.Sleep(time.Duration(rand.Intn(3000000)))
		client, err := elastic.NewClient(elastic.SetURL(esWriter.getURL()...), elastic.SetBasicAuth(esWriter.User, esWriter.Password))
		if err != nil {
			log.Errorf("create es client error: %v", err)
		}
		esWriter.client = client
	}
	stats.RegisterCountable("es_writer", esWriter, statOptions...)
}

func (esWriter *ESWriter) getURL() []string {
	var urls = make([]string, len(esWriter.Addresses))
	for index, address := range esWriter.Addresses {
		urls[index] = fmt.Sprintf("http://%s", address)
		log.Infof("connect to elasticsearch host: http://%s", address)
	}
	return urls
}

func (esWriter *ESWriter) releaseBulkFlow() {
	for _, flow := range esWriter.bulkFlow {
		flow.Release()
	}
	esWriter.bulkFlow = esWriter.bulkFlow[:0]
}

//Do flow写入es执行方法
func (esWriter *ESWriter) Do() {
	var timestamp = time.Duration(time.Now().UnixNano())
	items := make([]interface{}, QUEUE_FETCH_SIZE)
	n := esWriter.ESQueue.Gets(items)
	for _, item := range items[:n] {
		if item == nil {
			continue
		}
		flow, ok := item.(ESItem)
		if !ok {
			log.Warningf("item type invalid %T", item)
			continue
		}
		// 防止异常的时间戳，导致误删除数据
		if flow.EndTime() < timestamp+time.Hour && flow.EndTime() > timestamp-time.Hour {
			timestamp = flow.EndTime()
		}
		esWriter.bulkFlow = append(esWriter.bulkFlow, flow)
	}

	timeNow := time.Now().Unix()

	startTime := time.Duration(time.Now().UnixNano())

	index := esWriter.RetentionPolicy.GetAppIndex(esWriter.AppName, timestamp)

	var count = 0

	if len(esWriter.bulkFlow) >= BULK_SIZE || (len(esWriter.bulkFlow) != 0 &&
		(timeNow-int64(esWriter.lastBulkTime.Seconds()) >= MAX_BULK_WRITE_INTERVAL)) {

		if !esWriter.checkIndex(timestamp, index) {
			if len(esWriter.bulkFlow) >= BULK_SIZE*10 {
				log.Warningf("drop %v documents", len(esWriter.bulkFlow))
				esWriter.releaseBulkFlow()
			}
			return
		}
		bulkRequest := esWriter.client.Bulk()
		for _, item := range esWriter.bulkFlow {
			indexReq := elastic.NewBulkIndexRequest().Index(index).Type(esWriter.DataType).Doc(item)
			bulkRequest.Add(indexReq)
			count++
		}

		bulkResponse, err := bulkRequest.Do(context.TODO())
		if err != nil {
			log.Errorf("there is some error when bulkRequest, error: %v", err)
		}
		if bulkResponse == nil {
			log.Errorf("expected bulkResponse to be != nil; got nil")
		}

		if bulkRequest.NumberOfActions() != 0 {
			log.Errorf("expected bulkRequest.NumberOfActions %d; got %d", 0, bulkRequest.NumberOfActions())
		}

		/* 调整额外等待时间，使得整体不满载，修改opLoadFactor获得最佳等待时间 */
		if bulkResponse != nil {
			time.Sleep(time.Duration(bulkResponse.Took/esWriter.OpLoadFactor) * time.Millisecond)
		}

		esWriter.lastBulkTime = time.Duration(timeNow) * time.Second
		esWriter.releaseBulkFlow()
	}
	endTime := time.Duration(time.Now().UnixNano())

	if esWriter.maxExecTime < endTime-startTime {
		esWriter.maxExecTime = endTime - startTime
	}

	if esWriter.avgExecTime == 0 {
		esWriter.avgExecTime = endTime - startTime
	} else {
		esWriter.avgExecTime = (esWriter.avgExecTime + (endTime - startTime)) / 2
	}

	esWriter.totalWriteCount += int64(count)

}

func (esWriter *ESWriter) Run() {
	for {
		esWriter.Do()
	}
}

// 检查index是否存在
func (esWriter *ESWriter) checkIndex(timestamp time.Duration, index string) bool {
	indexTime := esWriter.RetentionPolicy.SplitSize.AlignTimestamp(timestamp)

	indexExists := true
	res, err := esWriter.client.IndexExists(index).Do(context.TODO())
	if err != nil {
		indexExists = false
		log.Errorf("check index exist error: %v", err)
	}
	if !res {
		indexExists = false
		log.Warningf("index %v not exist", index)
	}

	if indexTime > esWriter.lastIndexTime || !indexExists {
		go func() {
			start := time.Now()
			/* remove old indices */
			for _, expiredIndex := range esWriter.RetentionPolicy.GetAppExpiredIndices(esWriter.AppName, timestamp) {
				existRes, err := esWriter.client.IndexExists(expiredIndex).Do(context.TODO())
				if err != nil {
					log.Errorf("check index exist error: %v", err)
					break
				}
				if !existRes {
					log.Warningf("index %v not exist", expiredIndex)
					break
				}

				deleteRes, err := esWriter.client.DeleteIndex(expiredIndex).Do(context.TODO())
				if err != nil {
					log.Errorf("delete old index %s error: %v", expiredIndex, err)
					break
				}
				if deleteRes.Acknowledged {
					log.Debugf("deleted index %v", expiredIndex)
				} else {
					log.Warningf("delete old index %s failed", expiredIndex)
				}
			}
			log.Infof("delete expire indices finish(cost time: %s).", time.Since(start))
		}()
		/* create new index */
		if !indexExists {
			if !esWriter.checkTemplate() {
				time.Sleep(time.Second * 60)
				log.Warning("no index template exist, sleep 60s")
				return false
			}

			createIndexStart := time.Now()
			res, err := esWriter.client.CreateIndex(index).Body(esWriter.Mapping).Do(context.TODO())
			if err != nil {
				log.Errorf("create index(cost time: %s) error: %v", time.Since(createIndexStart), err)
			} else if res == nil {
				log.Warningf("create index(cost time: %s) %v failed", time.Since(createIndexStart), index)
			} else {
				log.Infof("create index(cost time: %s) %s success", time.Since(createIndexStart), index)
			}
		}
		esWriter.lastIndexTime = indexTime
	}

	return true
}

func (esWriter *ESWriter) checkTemplate() bool {
	getresp, err := esWriter.client.IndexGetTemplate().Name(esWriter.AppName).Do(context.TODO())
	if err != nil {
		log.Errorf("get template error: %v", err)
		return false
	}
	if getresp == nil {
		log.Warningf("get mapping of %v failed")
		return false
	}
	return true
}

func (esWriter *ESWriter) GetCounter() interface{} {
	counter := Counter{
		MaxExecTime:     int64(esWriter.maxExecTime),
		AvgExecTime:     int64(esWriter.avgExecTime),
		TotalWriteCount: esWriter.totalWriteCount,
	}
	esWriter.maxExecTime = 0
	esWriter.avgExecTime = 0
	esWriter.totalWriteCount = 0
	return &counter
}
