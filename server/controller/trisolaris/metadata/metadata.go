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

package metadata

import (
	"context"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var log = logging.MustGetLogger("trisolaris/metadata")

type MetaData struct {
	dbDataCache    *atomic.Value // *DBDataCache 数据库缓存
	platformDataOP *PlatformDataOP
	groupDataOP    *GroupDataOP
	tapType        *TapType
	policyDataOP   *PolicyDataOP
	startTime      int64
	chPlatformData chan struct{}
	chTapType      chan struct{}
	chPolicy       chan struct{}
	chGroup        chan struct{}
	config         *config.Config
	db             *gorm.DB
	ctx            context.Context
	cancel         context.CancelFunc
	ORGID
}

func NewMetaData(db *gorm.DB, cfg *config.Config, orgID int, pctx context.Context) *MetaData {
	ctx, cancel := context.WithCancel(pctx)
	dbDataCache := &atomic.Value{}
	dbDataCache.Store(newDBDataCache(ORGID(orgID), cfg))
	metaData := &MetaData{
		dbDataCache:    dbDataCache,
		tapType:        newTapType(db),
		chPlatformData: make(chan struct{}, 1),
		chTapType:      make(chan struct{}, 1),
		chPolicy:       make(chan struct{}, 1),
		chGroup:        make(chan struct{}, 1),
		config:         cfg,
		db:             db,
		ctx:            ctx,
		cancel:         cancel,
		ORGID:          ORGID(orgID),
	}
	metaData.platformDataOP = newPlatformDataOP(db, metaData)
	metaData.groupDataOP = newGroupDataOP(metaData)
	metaData.policyDataOP = newPolicyDaTaOP(metaData, cfg.BillingMethod)
	return metaData
}

func (m *MetaData) generateDbDataCache() {
	dbDataCache := newDBDataCache(m.ORGID, m.config)
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

func (m *MetaData) PutChPolicy() {
	select {
	case m.chPolicy <- struct{}{}:
	default:
	}
}

func (m *MetaData) PutChGroup() {
	select {
	case m.chGroup <- struct{}{}:
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

func (m *MetaData) GetGroupDataOP() *GroupDataOP {
	return m.groupDataOP
}

func (m *MetaData) GetTapTypes() []*trident.TapType {
	return m.tapType.getTapTypes()
}

func (m *MetaData) GetTridentGroups() []byte {
	return m.groupDataOP.getTridentGroups()
}

func (m *MetaData) GetTridentGroupsVersion() uint64 {
	return m.groupDataOP.getTridentGroupsVersion()
}

func (m *MetaData) GetDropletGroups() []byte {
	return m.groupDataOP.getDropletGroups()
}

func (m *MetaData) GetDropletGroupsVersion() uint64 {
	return m.groupDataOP.getDropletGroupsVersion()
}

func (m *MetaData) GetDropletPolicyVersion() uint64 {
	return m.policyDataOP.getDropletPolicyVersion()
}

func (m *MetaData) GetDropletPolicyStr() []byte {
	return m.policyDataOP.getDropletPolicyStr()
}

func (m *MetaData) GetVTapPolicyVersion(vtapID int, functions mapset.Set) uint64 {
	return m.policyDataOP.getVTapPolicyVersion(vtapID, functions)
}

func (m *MetaData) GetVTapPolicyString(vtapID int, functions mapset.Set) []byte {
	return m.policyDataOP.getVTapPolicyString(vtapID, functions)
}

func (m *MetaData) GetPlatformVips() []string {
	return m.config.PlatformVips
}

func (m *MetaData) GetStartTime() int64 {
	return m.startTime
}

func (m *MetaData) InitData(startTime int64) {
	m.startTime = startTime
	m.generateDbDataCache()
	m.platformDataOP.initData()
	m.groupDataOP.SetStartTime(startTime)
	m.groupDataOP.generateGroupData()
	m.tapType.generateTapTypes()
	m.policyDataOP.generatePolicyData()
}

func (m *MetaData) timedRefreshMetaData() {
	interval := time.Duration(m.config.MetaDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info(m.Log("start generate metaData from timed"))
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			m.groupDataOP.generateGroupData()
			m.policyDataOP.generatePolicyData()
			m.tapType.generateTapTypes()
			log.Info(m.Log("end generate metaData from timed"))
		case <-m.chPlatformData:
			log.Info(m.Log("start generate platform data from rpc"))
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			log.Info(m.Log("end generate platform data from rpc"))
		case <-m.chPolicy:
			log.Info(m.Log("start generate policy from rpc"))
			m.generateDbDataCache()
			m.groupDataOP.generateGroupData()
			m.policyDataOP.generatePolicyData()
			log.Info(m.Log("end generate policy from rpc"))
			pushmanager.Broadcast()
		case <-m.chGroup:
			log.Info(m.Log("start generate group from rpc"))
			m.generateDbDataCache()
			m.groupDataOP.generateGroupData()
			log.Info(m.Log("end generate group from rpc"))
			pushmanager.Broadcast()
		case <-m.chTapType:
			log.Info(m.Log("start generate tap type from rpc"))
			m.tapType.generateTapTypes()
			log.Info(m.Log("end generate tap type from rpc"))
		case <-m.ctx.Done():
			log.Info(m.Log("exit generate metaData"))
			return
		}
	}
}

func (m *MetaData) TimedRefreshMetaData() {
	go m.timedRefreshMetaData()
}
