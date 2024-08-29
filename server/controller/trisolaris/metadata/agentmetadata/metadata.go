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

package agentmetadata

import (
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/dbcache"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.agentmetadata")

type MetaData struct {
	dbDataCache          *atomic.Value // *DBDataCache 数据库缓存
	platformDataOP       *PlatformDataOP
	groupDataOP          *GroupDataOP
	policyDataOP         *PolicyDataOP
	captureNetworkTypeOP *CaptureNetworkTypeOP
	startTime            int64
	config               *config.Config
	db                   *gorm.DB
	ORGID
}

func NewMetaData(db *gorm.DB, cfg *config.Config, orgID int) *MetaData {
	dbDataCache := &atomic.Value{}
	dbDataCache.Store(NewDBDataCache(ORGID(orgID), cfg))
	metaData := &MetaData{
		dbDataCache:          dbDataCache,
		captureNetworkTypeOP: newCaptureNetworkTypeOP(db),
		config:               cfg,
		db:                   db,
		ORGID:                ORGID(orgID),
	}
	metaData.platformDataOP = newPlatformDataOP(db, metaData)
	metaData.groupDataOP = newGroupDataOP(metaData)
	metaData.policyDataOP = newPolicyDaTaOP(metaData, cfg.BillingMethod)
	return metaData

}

func (m *MetaData) GetDBDataCache() *DBDataCache {
	return m.dbDataCache.Load().(*DBDataCache)
}

func (m *MetaData) UpdateDBDataCache(d *DBDataCache) {
	m.dbDataCache.Store(d)
}

func (m *MetaData) GetPlatformDataOP() *PlatformDataOP {
	return m.platformDataOP
}

func (m *MetaData) GetPolicyDataOP() *PolicyDataOP {
	return m.policyDataOP
}

func (m *MetaData) GetCaptureNetworkTypes() []*agent.CaptureNetworkType {
	return m.captureNetworkTypeOP.getCaptureNetworkTypes()
}

func (m *MetaData) GetGroupDataOP() *GroupDataOP {
	return m.groupDataOP
}

func (m *MetaData) GetAgentGroups() []byte {
	return m.groupDataOP.getAgentGroups()
}

func (m *MetaData) GetAgentGroupsVersion() uint64 {
	return m.groupDataOP.getAgentGroupsVersion()
}

func (m *MetaData) GetAgentPolicyVersion(agentID int, functions mapset.Set) uint64 {
	return m.policyDataOP.getAgentPolicyVersion(agentID, functions)
}

func (m *MetaData) GetAgentPolicyString(agentID int, functions mapset.Set) []byte {
	return m.policyDataOP.getAgentPolicyString(agentID, functions)
}

func (m *MetaData) GetPlatformVips() []string {
	return m.config.PlatformVips
}

func (m *MetaData) GetStartTime() int64 {
	return m.startTime
}

func (m *MetaData) InitData(startTime int64) {
	m.startTime = startTime
	m.platformDataOP.initData()
	m.groupDataOP.SetStartTime(startTime)
	m.groupDataOP.generateGroupData()
	m.captureNetworkTypeOP.generateCaptureNetworkTypes()
	m.policyDataOP.generatePolicyData()
}

func (m *MetaData) TickerTrigger() {
	log.Info(m.Log("start generate metaData from timed"))
	m.platformDataOP.GeneratePlatformData()
	m.groupDataOP.generateGroupData()
	m.policyDataOP.generatePolicyData()
	m.captureNetworkTypeOP.generateCaptureNetworkTypes()
	log.Info(m.Log("end generate metaData from timed"))
}

func (m *MetaData) ChPlatformDataTrigger() {
	log.Info(m.Log("start generate platform data from rpc"))
	time.Sleep(time.Duration(m.config.PlatformDataRefreshDelayTime) * time.Second)
	log.Info("processing generate platform data from rpc")
	m.platformDataOP.GeneratePlatformData()
	log.Info(m.Log("end generate platform data from rpc"))
}

func (m *MetaData) ChPolicyTrigger() {
	log.Info(m.Log("start generate policy from rpc"))
	m.groupDataOP.generateGroupData()
	m.policyDataOP.generatePolicyData()
	log.Info(m.Log("end generate policy from rpc"))
}

func (m *MetaData) ChGroupTrigger() {
	log.Info(m.Log("start generate group from rpc"))
	m.groupDataOP.generateGroupData()
	log.Info(m.Log("end generate group from rpc"))

}

func (m *MetaData) ChCaptureNetworkTypeTrigger() {
	log.Info(m.Log("start generate capture network type from rpc"))
	m.captureNetworkTypeOP.generateCaptureNetworkTypes()
	log.Info(m.Log("end generate capture network type from rpc"))
}
