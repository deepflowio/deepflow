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

package unmarshaller

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/codec"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_metrics.unmarshaller")

const (
	QUEUE_BATCH_SIZE = 1024
	FLUSH_INTERVAL   = 5
	GET_MAX_SIZE     = 1024
	DOC_TIME_EXCEED  = 300
	HASH_SEED        = 17
)

var exportDataSources = []config.DataSourceID{config.NETWORK_1M, config.NETWORK_MAP_1M, config.NETWORK_1S, config.NETWORK_MAP_1S,
	config.APPLICATION_1M, config.APPLICATION_MAP_1M, config.APPLICATION_1S, config.APPLICATION_MAP_1S}

type QueueCache struct {
	values []interface{}
}

type Counter struct {
	DocCount        int64 `statsd:"doc-count"`
	ErrDocCount     int64 `statsd:"err-doc-count"`
	AverageDelay    int64 `statsd:"average-delay"`
	MaxDelay        int64 `statsd:"max-delay"`
	MinDelay        int64 `statsd:"min-delay"`
	ExpiredDocCount int64 `statsd:"expired-doc-count"`
	FutureDocCount  int64 `statsd:"future-doc-count"`
	DropDocCount    int64 `statsd:"drop-doc-count"`
	TotalTime       int64 `statsd:"total-time"`
	AvgTime         int64 `statsd:"avg-time"`

	FlowPortCount       int64 `statsd:"vtap-flow-port"`
	FlowPort1sCount     int64 `statsd:"vtap-flow-port-1s"`
	FlowEdgePortCount   int64 `statsd:"vtap-flow-edge-port"`
	FlowEdgePort1sCount int64 `statsd:"vtap-flow-edge-port-1s"`
	AclCount            int64 `statsd:"vtap-acl"`
	OtherCount          int64 `statsd:"other-db-count"`
}

type Unmarshaller struct {
	index              int
	platformData       *grpc.PlatformInfoTable
	disableSecondWrite bool
	unmarshallQueue    queue.QueueReader
	dbwriter           dbwriter.DbWriter
	queueBatchCache    QueueCache
	counter            *Counter
	tableCounter       [flow_metrics.METRICS_TABLE_ID_MAX + 1]int64
	exporters          *exporters.Exporters
	utils.Closable
}

func NewUnmarshaller(index int, platformData *grpc.PlatformInfoTable, disableSecondWrite bool, unmarshallQueue queue.QueueReader, dbwriter dbwriter.DbWriter, exporters *exporters.Exporters) *Unmarshaller {
	return &Unmarshaller{
		index:              index,
		platformData:       platformData,
		disableSecondWrite: disableSecondWrite,
		unmarshallQueue:    unmarshallQueue,
		counter:            &Counter{MaxDelay: -3600, MinDelay: 3600},
		dbwriter:           dbwriter,
		exporters:          exporters,
	}
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (u *Unmarshaller) isGoodDocument(docTime int64) bool {
	delay := time.Now().Unix() - docTime
	u.counter.DocCount++
	u.counter.AverageDelay += delay
	u.counter.MaxDelay = max(u.counter.MaxDelay, delay)
	u.counter.MinDelay = min(u.counter.MinDelay, delay)
	if delay > DOC_TIME_EXCEED {
		u.counter.ExpiredDocCount++
		return false
	}
	if delay < -DOC_TIME_EXCEED {
		u.counter.FutureDocCount++
		return false
	}
	return true
}

func (u *Unmarshaller) GetCounter() interface{} {
	var counter *Counter
	counter, u.counter = u.counter, &Counter{MaxDelay: -3600, MinDelay: 3600}

	if counter.DocCount != 0 {
		counter.AverageDelay /= counter.DocCount
		counter.AvgTime = counter.TotalTime / counter.DocCount
	} else {
		counter.MaxDelay = 0
		counter.MinDelay = 0
	}

	counter.FlowPortCount, u.tableCounter[flow_metrics.NETWORK_1M] = u.tableCounter[flow_metrics.NETWORK_1M], 0
	counter.FlowPort1sCount, u.tableCounter[flow_metrics.NETWORK_1S] = u.tableCounter[flow_metrics.NETWORK_1S], 0
	counter.FlowEdgePortCount, u.tableCounter[flow_metrics.NETWORK_MAP_1M] = u.tableCounter[flow_metrics.NETWORK_MAP_1M], 0
	counter.FlowEdgePort1sCount, u.tableCounter[flow_metrics.NETWORK_MAP_1S] = u.tableCounter[flow_metrics.NETWORK_MAP_1S], 0
	counter.AclCount, u.tableCounter[flow_metrics.TRAFFIC_POLICY_1M] = u.tableCounter[flow_metrics.TRAFFIC_POLICY_1M], 0
	counter.OtherCount, u.tableCounter[flow_metrics.METRICS_TABLE_ID_MAX] = u.tableCounter[flow_metrics.METRICS_TABLE_ID_MAX], 0

	return counter
}

func (u *Unmarshaller) putStoreQueue(doc app.Document) {
	queueCache := &u.queueBatchCache
	queueCache.values = append(queueCache.values, doc)

	if len(queueCache.values) >= QUEUE_BATCH_SIZE {
		u.dbwriter.Put(queueCache.values...)
		queueCache.values = queueCache.values[:0]
	}
}

func (u *Unmarshaller) flushStoreQueue() {
	queueCache := &u.queueBatchCache
	if len(queueCache.values) > 0 {
		u.dbwriter.Put(queueCache.values...)
		queueCache.values = queueCache.values[:0]
	}
}

func DecodeForQueueMonitor(item interface{}) (interface{}, error) {
	var ret interface{}
	bytes, ok := item.(*receiver.RecvBuffer)
	if !ok {
		return nil, errors.New("only support data(type: RecvBuffer) to unmarshall")
	}

	ret, err := decodeForDebug(bytes.Buffer[bytes.Begin:bytes.End])
	return ret, err
}

type BatchDocument []app.Document

func (bd BatchDocument) String() string {
	docs := []app.Document(bd)
	str := fmt.Sprintf("batch msg num=%d\n", len(docs))
	for i, doc := range docs {
		str += fmt.Sprintf("%d%s", i, doc.String())
	}
	return str
}

func decodeForDebug(b []byte) (BatchDocument, error) {
	if b == nil {
		return nil, errors.New("No input byte")
	}

	decoder := &codec.SimpleDecoder{}
	decoder.Init(b)
	docs := make([]app.Document, 0)

	for !decoder.IsEnd() {
		doc, err := app.DecodeForQueueMonitor(decoder)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return BatchDocument(docs), nil
}

func (u *Unmarshaller) QueueProcess() {
	common.RegisterCountableForIngester("unmarshaller", u, stats.OptionStatTags{"thread": strconv.Itoa(u.index)})
	rawDocs := make([]interface{}, GET_MAX_SIZE)
	decoder := &codec.SimpleDecoder{}
	pbDoc := pb.NewDocument()
	for !u.Closed() {
		n := u.unmarshallQueue.Gets(rawDocs)
		start := time.Now()
		for i := 0; i < n; i++ {
			value := rawDocs[i]
			if recvBytes, ok := value.(*receiver.RecvBuffer); ok {
				bytes := recvBytes.Buffer[recvBytes.Begin:recvBytes.End]
				decoder.Init(bytes)
				for !decoder.Failed() && !decoder.IsEnd() {
					pbDoc.ResetAll()
					doc, err := app.DecodePB(decoder, pbDoc)
					if err != nil {
						u.counter.ErrDocCount++
						log.Warningf("Decode failed, bytes len=%d err=%s", len([]byte(bytes)), err)
						break
					}
					u.isGoodDocument(int64(doc.Time()))

					// 秒级数据是否写入
					if u.disableSecondWrite &&
						doc.Flag()&app.FLAG_PER_SECOND_METRICS != 0 {
						doc.Release()
						continue
					}

					if err := DocumentExpand(doc, u.platformData); err != nil {
						log.Debug(err)
						u.counter.DropDocCount++
						doc.Release()
						continue
					}

					tableID, err := doc.TableID()
					if err != nil {
						log.Debug(err)
						u.counter.DropDocCount++
						doc.Release()
						continue
					}
					u.tableCounter[tableID]++

					u.export(doc)
					u.putStoreQueue(doc)
				}
				receiver.ReleaseRecvBuffer(recvBytes)
			} else if value == nil { // flush ticker
				u.flushStoreQueue()
				u.export(nil)
			} else {
				log.Warning("get unmarshall queue data type wrong")
			}
		}
		u.counter.TotalTime += int64(time.Since(start))
	}
}

func (u *Unmarshaller) export(doc app.Document) {
	if u.exporters == nil {
		return
	}
	if doc == nil {
		// flush data
		for _, v := range exportDataSources {
			u.exporters.Put(uint32(v), u.index, nil)
		}
	}

	switch v := doc.(type) {
	case *app.DocumentFlow:
		u.exporters.Put(v.DataSource(), u.index, (*ExportDocumentFlow)(v))
	case *app.DocumentApp:
		u.exporters.Put(v.DataSource(), u.index, (*ExportDocumentApp)(v))
	case *app.DocumentUsage:
		u.exporters.Put(v.DataSource(), u.index, (*ExportDocumentUsage)(v))
	}
}
