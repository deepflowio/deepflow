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

package flow_tag

import (
	"fmt"
	"strconv"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	WRITER_QUEUE_COUNT   = 1
	WRITER_QUEUE_SIZE    = 64 << 10
	WRITER_BATCH_SIZE    = 32 << 10
	WRITER_FLUSH_TIMEOUT = 10
)

type AppServiceCounter struct {
	CacheExpiredCount int64 `statsd:"cache-expired-count"`
	CacheAddCount     int64 `statsd:"cache-add-count"`
	CacheHitCount     int64 `statsd:"cache-hit-count"`
	CacheCount        int64 `statsd:"cache-count"`
}

type AppServiceTagWriter struct {
	ckdbAddrs    *[]string
	ckdbUsername string
	ckdbPassword string

	ckwriter *ckwriter.CKWriter

	Cache             *lru.Cache[AppServiceTag, uint32]
	CacheFlushTimeout uint32
	CacheKeyBuf       AppServiceTag

	counter *AppServiceCounter
	utils.Closable
}

func NewAppServiceTagWriter(
	decoderIndex int,
	db, msgType string,
	ttl int,
	partition ckdb.TimeFuncType,
	config *config.Config) (*AppServiceTagWriter, error) {
	w := &AppServiceTagWriter{
		ckdbAddrs:         config.CKDB.ActualAddrs,
		ckdbUsername:      config.CKDBAuth.Username,
		ckdbPassword:      config.CKDBAuth.Password,
		Cache:             lru.NewCache[AppServiceTag, uint32](int(config.FlowTagCacheMaxSize)),
		CacheFlushTimeout: config.FlowTagCacheFlushTimeout,
		counter:           &AppServiceCounter{},
	}
	var err error
	tableName := fmt.Sprintf("%s_app_service", db)
	w.ckwriter, err = ckwriter.NewCKWriter(
		*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		fmt.Sprintf("tag-%s-%s-%d", tableName, msgType, decoderIndex),
		config.CKDB.TimeZone,
		GenAppServiceTagCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, tableName, config.CKDB.Type, ttl, partition),
		WRITER_QUEUE_COUNT, WRITER_QUEUE_SIZE, WRITER_BATCH_SIZE, WRITER_FLUSH_TIMEOUT, config.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.ckwriter.Run()

	common.RegisterCountableForIngester("app_service_tag_writer", w, stats.OptionStatTags{"type": msgType, "decoder_index": strconv.Itoa(decoderIndex)})
	return w, nil
}

func (w *AppServiceTagWriter) Write(time uint32, table, appService, appInstance string, orgID, teamID uint16) {
	w.CacheKeyBuf.Table = table
	w.CacheKeyBuf.AppService = appService
	w.CacheKeyBuf.AppInstance = appInstance
	w.CacheKeyBuf.OrgId = orgID
	w.CacheKeyBuf.TeamID = teamID

	if old, get := w.Cache.AddOrGet(w.CacheKeyBuf, time); get {
		if old+w.CacheFlushTimeout >= time {
			w.counter.CacheHitCount++
			return
		} else {
			w.counter.CacheExpiredCount++
			w.Cache.Add(w.CacheKeyBuf, time)
		}
	}
	serviceTag := AcquireAppServiceTag()
	*serviceTag = w.CacheKeyBuf
	serviceTag.Time = time

	w.ckwriter.Put(serviceTag)
}

func (w *AppServiceTagWriter) GetCounter() interface{} {
	var counter *AppServiceCounter
	counter, w.counter = w.counter, &AppServiceCounter{}
	counter.CacheCount = int64(w.Cache.Len())
	return counter
}
