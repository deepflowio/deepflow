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

package trisolaris

import (
	"context"
	"math/rand"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/patrickmn/go-cache"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/election"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/kubernetes"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/node"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris")

type Trisolaris struct {
	config         *config.Config
	metaData       *metadata.MetaData
	vTapInfo       *vtap.VTapInfo
	nodeInfo       *node.NodeInfo
	kubernetesInfo *kubernetes.KubernetesInfo
	startTime      int64
	mDB            *metadb.DB
	ctx            context.Context
	cancel         context.CancelFunc
}

type TrisolarisManager struct {
	orgToTrisolaris [utils.ORG_ID_INDEX_MAX]*Trisolaris
	refreshOP       *refresh.RefreshOP
	teamIDToOrgID   map[string]int
	teamIDStrToInt  map[string]int
	config          *config.Config
	defaultDB       *gorm.DB
	startTime       int64
	orgIDData       *trident.OrgIDsResponse
	imageCache      *cache.Cache

	ctx    context.Context
	cancel context.CancelFunc
}

var trisolarisManager *TrisolarisManager

func GetMetaData(orgID int) *metadata.MetaData {
	trisolaris := GetTrisolaris(orgID)
	if trisolaris == nil {
		return nil
	}
	return trisolaris.metaData
}

func GetOrgInfoByTeamID(teamIDStr string) (orgID int, teamID int) {
	if trisolarisManager == nil {
		return
	}
	orgID, teamID = trisolarisManager.GetOrgInfoByTeamID(teamIDStr)
	return
}

func GetOrgIDByTeamID(teamID string) int {
	if trisolarisManager == nil {
		return 0
	}
	return trisolarisManager.GetOrgIDByTeamID(teamID)
}

func GetPushEnabled() bool {
	if trisolarisManager == nil {
		return false
	}
	return trisolarisManager.GetPushEnabled()
}

func GetPushDelayRand() int64 {
	if trisolarisManager == nil {
		return 0
	}
	return trisolarisManager.GetPushDelayRand()
}

func GetORGVTapInfo(orgID int) *vtap.VTapInfo {
	if utils.CheckOrgID(orgID) == false || trisolarisManager == nil {
		return nil
	}
	return trisolarisManager.GetVTapInfo(orgID)
}

func GetORGNodeInfo(orgID int) *node.NodeInfo {
	trisolaris := GetTrisolaris(orgID)
	if trisolaris == nil {
		return nil
	}
	return trisolaris.nodeInfo
}

func GetOrgIDsData() *trident.OrgIDsResponse {
	if trisolarisManager == nil {
		return &trident.OrgIDsResponse{}
	}

	return trisolarisManager.orgIDData
}

func TeamIDToTrisolaris(teamID string) *Trisolaris {
	if trisolarisManager == nil {
		log.Errorf("failed to get trisolaris manager")
		return nil
	}
	return trisolarisManager.orgToTrisolaris[GetOrgIDByTeamID(teamID)]
}

func GetGKubernetesInfo(teamID string) *kubernetes.KubernetesInfo {
	tri := TeamIDToTrisolaris(teamID)
	if tri == nil {
		log.Errorf("failed to get kubernetes info for teamID: %s", teamID)
		return nil
	}
	return tri.kubernetesInfo
}

func GetConfig() *config.Config {
	return trisolarisManager.config
}

func GetDefaultDB() *gorm.DB {
	return trisolarisManager.defaultDB
}

func GetBillingMethod() string {
	return trisolarisManager.config.BillingMethod
}

func GetGrpcPort() int {
	return trisolarisManager.config.GetGrpcPort()
}

func GetIngesterPort() int {
	return trisolarisManager.config.GetIngesterPort()
}

func GetIsRefused() bool {
	return trisolarisManager.config.GetNoTeamIDRefused()
}

func GetAllAgentConnectToNatIP() bool {
	return trisolarisManager.config.GetAllAgentConnectToNatIP()
}

func GetTrisolaris(orgID int) *Trisolaris {
	if utils.CheckOrgID(orgID) == false || trisolarisManager == nil {
		return nil
	}

	return trisolarisManager.orgToTrisolaris[orgID]
}

func PutPlatformData(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.metaData.PutChPlatformData()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.metaData.PutChPlatformData()
		}
	}
}

func PutTapType(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.metaData.PutChTapType()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.metaData.PutChTapType()
		}
	}
}

func PutNodeInfo(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.nodeInfo.PutChNodeInfo()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.nodeInfo.PutChNodeInfo()
		}
	}
}

func PutVTapCache(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.vTapInfo.PutVTapCacheRefresh()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.vTapInfo.PutVTapCacheRefresh()
		}
	}
}

func PutFlowACL(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.metaData.PutChPolicy()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.metaData.PutChPolicy()
		}
	}
}

func PutGroup(orgID int) {
	if trisolarisManager == nil {
		return
	}
	if orgID == 0 {
		for _, trisolaris := range trisolarisManager.orgToTrisolaris {
			if trisolaris != nil {
				trisolaris.metaData.PutChGroup()
			}
		}
	} else {
		trisolaris := GetTrisolaris(orgID)
		if trisolaris != nil {
			trisolaris.metaData.PutChGroup()
		}
	}
}

func SetImageCache(key string, value any) {
	if trisolarisManager == nil {
		return
	}
	log.Warningf("image cache set (%s)", key)
	trisolarisManager.imageCache.SetDefault(key, value)
}

func GetImageCache(key string) (any, bool) {
	if trisolarisManager == nil {
		return nil, false
	}
	log.Debugf("image cache get (%s)", key)
	return trisolarisManager.imageCache.Get(key)
}

func DeleteImageCache(key string) {
	if trisolarisManager == nil {
		return
	}
	log.Debugf("image cache delete (%s)", key)
	trisolarisManager.imageCache.Delete(key)
}

func getStartTime() int64 {
	startTime := int64(0)
	for {
		startTime = election.GetAcquireTime()
		if startTime == 0 {
			log.Errorf("get start time(%d) failed", startTime)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}

	log.Infof("get start time(%d) success", startTime)

	return startTime
}

func (t *Trisolaris) Start() {
	log.Infof("start ORG(id=%d database=%s) data generate", t.mDB.ORGID, t.mDB.Name)
	t.metaData.GetPlatformDataOP().RegisteNotifyIngesterDatachanged(
		t.nodeInfo.NotifyBasePlatformDataChanged)
	t.metaData.InitData(t.startTime) // 需要先初始化
	go func() {
		go t.metaData.TimedRefreshMetaData()
		go t.kubernetesInfo.TimedRefreshClusterID()
		go t.vTapInfo.Run()
		go t.nodeInfo.TimedRefreshNodeCache()
	}()
}

func (t *Trisolaris) Stop() {
	log.Infof("exit ORG(id=%d database=%s) data generate", t.mDB.ORGID, t.mDB.Name)
	t.cancel()
}

func (t *Trisolaris) GetVTapInfo() *vtap.VTapInfo {
	return t.vTapInfo
}

func (t *Trisolaris) GetNodeInfo() *node.NodeInfo {
	return t.nodeInfo
}

func NewTrisolaris(cfg *config.Config, mDB *metadb.DB, pctx context.Context, startTime int64) *Trisolaris {
	ctx, cancel := context.WithCancel(pctx)
	metaData := metadata.NewMetaData(mDB.DB, cfg, mDB.ORGID, ctx)
	trisolaris := &Trisolaris{
		config:         cfg,
		metaData:       metaData,
		vTapInfo:       vtap.NewVTapInfo(mDB.DB, metaData, cfg, mDB.ORGID, ctx),
		nodeInfo:       node.NewNodeInfo(mDB.DB, metaData, cfg, mDB.ORGID, ctx),
		kubernetesInfo: kubernetes.NewKubernetesInfo(mDB.DB, cfg, mDB.ORGID, ctx),
		startTime:      startTime,
		mDB:            mDB,
		ctx:            ctx,
		cancel:         cancel,
	}

	return trisolaris
}

func NewTrisolarisManager(cfg *config.Config, db *gorm.DB) *TrisolarisManager {
	if trisolarisManager == nil {
		cfg.Convert()
		ctx, cancel := context.WithCancel(context.Background())
		trisolarisManager = &TrisolarisManager{
			orgToTrisolaris: [utils.ORG_ID_INDEX_MAX]*Trisolaris{},
			refreshOP:       refresh.NewRefreshOP(db, cfg.NodeIP),
			teamIDToOrgID:   make(map[string]int),
			teamIDStrToInt:  make(map[string]int),
			config:          cfg,
			defaultDB:       db,
			orgIDData:       &trident.OrgIDsResponse{},
			imageCache:      cache.New(time.Duration(cfg.ImageExpire)*time.Second, 10*time.Minute),

			ctx:    ctx,
			cancel: cancel,
		}
	}

	return trisolarisManager
}

func (m *TrisolarisManager) Start() error {
	go m.refreshOP.TimedRefreshIPs()
	m.startTime = getStartTime()
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("get orgIDs : %v", orgIDs)
	trisolaris := NewTrisolaris(m.config, metadb.DefaultDB, m.ctx, m.startTime)
	m.orgToTrisolaris[DEFAULT_ORG_ID] = trisolaris
	go trisolaris.Start()
	orgIDsUint32 := make([]uint32, len(orgIDs), len(orgIDs))
	for index, orgID := range orgIDs {
		orgIDsUint32[index] = uint32(orgID)
		if utils.CheckOrgID(orgID) == false || orgID == DEFAULT_ORG_ID {
			continue
		}
		orgDB, err := metadb.GetDB(orgID)
		if err != nil {
			log.Error(err)
			continue
		}
		trisolaris := NewTrisolaris(m.config, orgDB, m.ctx, m.startTime)
		m.orgToTrisolaris[orgID] = trisolaris
		go trisolaris.Start()
	}
	m.orgIDData = &trident.OrgIDsResponse{
		OrgIds:     orgIDsUint32,
		UpdateTime: proto.Uint32(uint32(time.Now().Unix())),
	}
	go m.TimedCheckORG()
	m.getTeamData(orgIDs)
	log.Infof("finish orgdata init %v", orgIDs)
	return nil
}

func (m *TrisolarisManager) getTeamData(orgIDs []int) {
	//  The CE does not involve organization-related data
	if m.config.GetFPermitConfig().Enabled == false {
		return
	}
	teamIDToOrgID := make(map[string]int)
	teamIDStrToInt := make(map[string]int)
	for _, orgID := range orgIDs {
		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Error(err)
			continue
		}
		teams, err := dbmgr.DBMgr[metadbmodel.Team](db.DB).Gets()
		if err != nil {
			log.Errorf("get org(id=%d) team failed, err(%s)", orgID, err)
			continue
		}
		for _, team := range teams {
			teamIDToOrgID[team.ShortLcuuid] = orgID
			teamIDStrToInt[team.ShortLcuuid] = team.TeamID
		}
	}

	m.teamIDToOrgID = teamIDToOrgID
	m.teamIDStrToInt = teamIDStrToInt
}

func (m *TrisolarisManager) TeamIDLcuuidToInt(teamID string) int {
	if len(teamID) == 0 {
		return DEFAULT_TEAM_ID
	}
	return m.teamIDStrToInt[teamID]
}

func (m *TrisolarisManager) GetOrgIDByTeamID(teamID string) int {
	if len(teamID) == 0 {
		return DEFAULT_ORG_ID
	}
	return m.teamIDToOrgID[teamID]
}

func (m *TrisolarisManager) GetOrgInfoByTeamID(teamID string) (int, int) {
	if len(teamID) == 0 {
		return DEFAULT_ORG_ID, DEFAULT_TEAM_ID
	}
	return m.teamIDToOrgID[teamID], m.teamIDStrToInt[teamID]
}

func (m *TrisolarisManager) PutVTapCacheRefresh(orgID int) {
	if utils.CheckOrgID(orgID) == false {
		return
	}
	trisolaris := m.orgToTrisolaris[orgID]
	if trisolaris != nil {
		trisolaris.vTapInfo.PutVTapCacheRefresh()
	}
}

func (m *TrisolarisManager) GetVTapInfo(orgID int) *vtap.VTapInfo {
	if utils.CheckOrgID(orgID) == false {
		log.Errorf("check orgID: %d failed", orgID)
		return nil
	}
	trisolaris := m.orgToTrisolaris[orgID]
	if trisolaris == nil {
		log.Errorf("get orgID: %d failed", orgID)
		return nil
	}
	return trisolaris.vTapInfo
}

func (m *TrisolarisManager) GetVTapCache(orgID int, key string) *vtap.VTapCache {
	vttridentnfo := m.GetVTapInfo(orgID)
	if vttridentnfo != nil {
		return vttridentnfo.GetVTapCache(key)
	}
	return nil
}

func (m *TrisolarisManager) checkORG() {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
	}

	orgIDsUint32 := make([]uint32, len(orgIDs), len(orgIDs))
	for index, orgID := range orgIDs {
		orgIDsUint32[index] = uint32(orgID)
	}
	m.orgIDData = &trident.OrgIDsResponse{
		OrgIds: orgIDsUint32,
	}

	for orgID, trisolaris := range m.orgToTrisolaris {
		if orgID == DEFAULT_ORG_ID {
			continue
		}
		if utils.Find[int](orgIDs, orgID) == false {
			if trisolaris != nil {
				m.orgToTrisolaris[orgID] = nil
				trisolaris.Stop()
			}
		} else {
			if trisolaris == nil {
				orgDB, err := metadb.GetDB(orgID)
				if err != nil {
					log.Error(err)
					continue
				}
				trisolaris := NewTrisolaris(m.config, orgDB, m.ctx, m.startTime)
				m.orgToTrisolaris[orgID] = trisolaris
				go trisolaris.Start()
			}
		}
	}
	m.getTeamData(orgIDs)
}

func (m *TrisolarisManager) TimedCheckORG() {
	interval := time.Duration(m.config.ORGDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start check org data from timed")
			m.checkORG()
			log.Info("end check org data from timed")
		}
	}
}

func (m *TrisolarisManager) GetPushEnabled() bool {
	return m.config.Push.Enabled
}

func (m *TrisolarisManager) GetPushDelayRand() int64 {
	if m.config.Push.DelayMax == 0 {
		return 0
	}
	seed := time.Now().UnixNano()
	return int64(rand.New(rand.NewSource(seed)).Intn(1000 * m.config.Push.DelayMax))
}
