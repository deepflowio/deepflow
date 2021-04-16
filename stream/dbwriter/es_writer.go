package dbwriter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/olivere/elastic"
	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"

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
	Replica           int
	Tiering           bool
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
	newIndex          string
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
	// 如果升级创建了newIndex，则写入newIndex
	if index < esWriter.newIndex && strings.HasPrefix(esWriter.newIndex, index) {
		index = esWriter.newIndex
	}

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
	// 每次启动先创建template
	for !esWriter.createTemplate() {
		time.Sleep(time.Minute)
	}
	// 判断当前的index mappings和template是否匹配，若不匹配则创建新的index
	esWriter.createNewIndexIfNeed()

	for {
		esWriter.Do()
	}
}

// 若当前的index和template不匹配，则新建index名为原index + 后缀"_[0-9][0-9]"
// 当多主机，多线程同时执行时，都是从index开始依次匹配后缀"_[0-9][0-9]"的index，并判断是否和template一致,几种情况
//   - 存在， 但不匹配，查找下一个INDEX
//   - 不存在, 再次put template，并创建新的INDEX
//   - 存在且匹配，结束
//  存在的风险: 如果存在一个旧版本的droplet最后复位了，且没有升级成功。会导致template变为老的，导致其他节点建立的index错误。
//     - 解决方法: 需要保证最终的droplet版本都一致
func (esWriter *ESWriter) createNewIndexIfNeed() {
	var i int
	index := esWriter.RetentionPolicy.GetAppIndex(esWriter.AppName, time.Duration(time.Duration(time.Now().UnixNano())))
	newIndex := index
	for {
		if i != 0 {
			newIndex = index + fmt.Sprintf("_%02d", i)
		}
		exist, err := esWriter.client.IndexExists(newIndex).Do(context.TODO())
		if err != nil {
			log.Warningf("check index(%s) is exist failed: %s", newIndex, err)
			time.Sleep(time.Minute)
			continue
		}

		if exist {
			// 如果存在就判断是否匹配
			match, err := esWriter.checkTemplateMatchIndexMappings(newIndex)
			if err != nil {
				log.Warningf("check index(%s) mappings failed: %s", newIndex, err)
				time.Sleep(time.Minute)
				continue
			}
			if match {
				if newIndex == index {
					return
				}
				esWriter.newIndex = newIndex
				log.Infof("New index is(%s)", newIndex)
				return
			} else {
				// 若不匹配，则判断下一个index
				i++
			}
		} else {
			// 再put一次template，防止被其他进程put了老的template
			if !esWriter.createTemplate() {
				time.Sleep(time.Second * 20)
				continue
			}
			// 不存在就建立一个，再判断是否匹配
			if _, err := esWriter.client.CreateIndex(newIndex).Body(esWriter.Mapping).Do(context.TODO()); err != nil {
				log.Warningf("create index(%s) failed: %s", newIndex, err)
				time.Sleep(time.Minute)
				continue
			}
			log.Infof("create index(%s)", newIndex)
		}
	}
}

func (esWriter *ESWriter) checkTemplateMatchIndexMappings(index string) (bool, error) {
	indexMappings, err := esWriter.client.GetMapping().Index(index).Do(context.TODO())
	if err != nil {
		log.Warningf("get index(%s) mappings failed: %s", index, err)
		return false, err
	}
	mps, ok := indexMappings[index].(map[string]interface{})
	if !ok {
		log.Infof("index(%s) mappings is not exist", index)
		return false, nil
	}
	mp, ok := mps["mappings"].(map[string]interface{})
	if !ok {
		log.Info("Index mappings not contains 'mappings'")
		return false, nil
	}

	if checkMappingsContainsSubmappings(mp, DFMappingsJson[esWriter.AppName]) {
		log.Infof("index(%s) mappings contains template(%s)", index, esWriter.AppName)
		return true, nil
	}
	return false, nil
}

func checkMappingsContainsSubmappings(mappings, submappings map[string]interface{}) bool {
	flow := submappings["flow"].(map[string]interface{})
	properties := flow["properties"].(map[string]interface{})
	for k, v := range properties {
		if !checkMappingsContainsProperty(mappings, k, v.(map[string]interface{})) {
			return false
		}
	}
	return true
}

func checkMappingsContainsProperty(mappings map[string]interface{}, key string, value map[string]interface{}) bool {
	flow, ok := mappings["flow"].(map[string]interface{})
	if !ok {
		log.Info("Index mappings not contains 'flow'")
		return false
	}
	properties, ok := flow["properties"].(map[string]interface{})
	if !ok {
		log.Info("Index mappings not contains 'properties'")
		return false
	}
	property, ok := properties[key].(map[string]interface{})
	if !ok {
		log.Infof("template key(%s) is not in index mappings", key)
		return false
	}

	if property["type"] == value["type"] &&
		property["index"] == value["index"] &&
		property["store"] == value["store"] {
		return true
	}
	log.Infof("template key(%s) value(%+v) is not equal index mappings value(%+v)", key, value, property)
	return false
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
					continue
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
				if !esWriter.createTemplate() {
					time.Sleep(time.Second * 60)
					log.Warning("no index template exist, sleep 60s")
					return false
				}
			}

			createIndexStart := time.Now()
			res, err := esWriter.client.CreateIndex(index).Body(esWriter.Mapping).Do(context.TODO())
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Infof("create index(cost time: %s) info: %v", time.Since(createIndexStart), err)
				} else {
					log.Errorf("create index(cost time: %s) error: %v", time.Since(createIndexStart), err)
				}
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
	_, err := esWriter.client.IndexGetTemplate().Name(esWriter.AppName).Do(context.TODO())
	if err != nil {
		log.Errorf("get template error: %v", err)
		return false
	}
	return true
}

func (esWriter *ESWriter) createTemplate() bool {
	putTemplate := esWriter.client.IndexPutTemplate(esWriter.AppName)
	data := buildJsonBody(esWriter.AppName, esWriter.Replica, esWriter.Tiering)
	putTemplate.BodyString(data)

	resp, err := putTemplate.Do(context.TODO())
	if err != nil {
		log.Errorf("create template error: %v data:%s", err, data)
		return false
	}
	log.Infof("create template(%s) result(%+v)", esWriter.AppName, resp)
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

func getMismatchIndexs(client *elastic.Client, name string) ([]string, error) {
	// 获取index的所有mappings
	allMappings, err := client.GetMapping().Index(name + common.LOG_SUFFIX).Do(context.TODO())
	if err != nil {
		log.Warningf("Get mappings(%s) failed: %s", name+common.LOG_SUFFIX, err)
		return nil, err
	}

	mismatchIndexs := make([]string, 0)
	for index, mappings := range allMappings {
		mapping, ok := mappings.(map[string]interface{})
		if !ok {
			continue
		}
		theMapping, ok := mapping["mappings"].(map[string]interface{})
		if !ok {
			continue
		}

		if !checkMappingsContainsSubmappings(theMapping, DFMappingsJson[name]) {
			mismatchIndexs = append(mismatchIndexs, index)
		}
	}
	if len(mismatchIndexs) == 0 {
		log.Infof("All indexs(%s) mappings is matched.", name)
		return nil, nil
	}
	log.Infof("Mismatch indexs(%v)", mismatchIndexs)
	return mismatchIndexs, nil
}

func deleteIndexs(client *elastic.Client, indexs []string) error {
	for _, index := range indexs {
		if _, err := client.DeleteIndex(index).Do(context.TODO()); err != nil {
			log.Warningf("delete index(%s) failed: %s", index, err)
			return err
		}
		log.Infof("Delete index(%s)", index)
	}
	return nil
}

func RegisterESIndexHandleCommand(esHostPorts []string, esUser, esPassword string) *cobra.Command {
	esURLs := []string{}
	for _, hp := range esHostPorts {
		esURLs = append(esURLs, "http://"+hp)
	}
	cmd := &cobra.Command{
		Use:   "es-mismatch-indexs",
		Short: "show/delete mismatch indexs",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show | del'.\n")
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "show mismatch indexs",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := elastic.NewClient(elastic.SetURL(esURLs...), elastic.SetBasicAuth(esUser, esPassword))
			if err != nil {
				fmt.Println("Show mismatch index failed: ", err)
				return
			}
			for name, _ := range DFMappings {
				getMismatchIndexs(client, name)
			}
		},
	}
	del := &cobra.Command{
		Use:   "del",
		Short: "del mismatch indexs",
		Run: func(cmd *cobra.Command, args []string) {
			client, err := elastic.NewClient(elastic.SetURL(esURLs...), elastic.SetBasicAuth(esUser, esPassword))
			if err != nil {
				fmt.Println("Delete mismatch indexs failed: ", err)
				return
			}
			for name, _ := range DFMappings {
				misMismatchs, err := getMismatchIndexs(client, name)
				if err != nil {
					fmt.Printf("get index(%s) misMismatchMappings failed: %s", name, err)
					continue
				}
				deleteIndexs(client, misMismatchs)
			}
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(del)
	return cmd
}
