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

package metadata

import (
	"gorm.io/gorm"
	"sync/atomic"
	"time"

	"github.com/deepflowys/deepflow/message/trident"
	"github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/controller/trisolaris/config"
)

var log = logging.MustGetLogger("trisolaris/metadata")

type MetaData struct {
	dbDataCache    *atomic.Value // *DBDataCache 数据库缓存
	platformDataOP *PlatformDataOP
	serviceDataOP  *ServiceDataOP
	tapType        *TapType
	chPlatformData chan struct{}
	chTapType      chan struct{}
	config         *config.Config
	db             *gorm.DB
}

func NewMetaData(db *gorm.DB, cfg *config.Config) *MetaData {
	dbDataCache := &atomic.Value{}
	dbDataCache.Store(newDBDataCache())
	metaData := &MetaData{
		dbDataCache:    dbDataCache,
		tapType:        newTapType(db),
		chPlatformData: make(chan struct{}, 1),
		chTapType:      make(chan struct{}, 1),
		config:         cfg,
		db:             db,
	}
	metaData.platformDataOP = newPlatformDataOP(db, metaData)
	metaData.serviceDataOP = newServiceDataOP(metaData)
	return metaData
}

func (m *MetaData) generateDbDataCache() {
	dbDataCache := newDBDataCache()
	dbDataCache.GetDataCacheFromDB(m.db)
	m.updateDBDataCache(dbDataCache)
}

func (m *MetaData) GetDBDataCache() *DBDataCache {
	return m.dbDataCache.Load().(*DBDataCache)
}

func (m *MetaData) updateDBDataCache(d *DBDataCache) {
	m.dbDataCache.Store(d)
}

func (m *MetaData) PutChPlatformData() {
	select {
	case m.chPlatformData <- struct{}{}:
	default:
	}
}

func (m *MetaData) PutChTapType() {
	select {
	case m.chTapType <- struct{}{}:
	default:
	}
}

func (m *MetaData) GetPlatformDataOP() *PlatformDataOP {
	return m.platformDataOP
}

func (m *MetaData) GetServiceDataOP() *ServiceDataOP {
	return m.serviceDataOP
}

func (m *MetaData) GetTapTypes() []*trident.TapType {
	return m.tapType.getTapTypes()
}

func (m *MetaData) InitData() {
	m.generateDbDataCache()
	m.platformDataOP.initData()
	m.serviceDataOP.GenerateServiceData()
	m.tapType.generateTapTypes()
}

func (m *MetaData) TimedRefreshPlatformData() {
	interval := time.Duration(m.config.MetaDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate platform data from timed")
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			m.serviceDataOP.GenerateServiceData()
			log.Info("end generate platform data from timed")
		case <-m.chPlatformData:
			log.Info("start generate platform data from rpc")
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			m.serviceDataOP.GenerateServiceData()
			log.Info("end generate platform data from rpc")
		}
	}
}

func (m *MetaData) TimedRefreshTapType() {
	interval := time.Duration(m.config.MetaDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate tap type from timed")
			m.tapType.generateTapTypes()
			log.Info("end generate tap type from timed")
		case <-m.chTapType:
			log.Info("start generate tap type from rpc")
			m.tapType.generateTapTypes()
			log.Info("end generate tap type from rpc")
		}
	}
}

func (m *MetaData) TimedRefreshMetaData() {
	go m.TimedRefreshPlatformData()
	go m.TimedRefreshTapType()
}
