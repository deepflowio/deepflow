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
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/election"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/kubernetes"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/node"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
)

var log = logging.MustGetLogger("trisolaris")

type Trisolaris struct {
	config         *config.Config
	metaData       *metadata.MetaData
	vTapInfo       *vtap.VTapInfo
	nodeInfo       *node.NodeInfo
	kubernetesInfo *kubernetes.KubernetesInfo
	startTime      int64
	mDB            *mysql.DB
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

	// tsdb data
	platformData          *atomic.Value // *metadata.PlatformData
	groupData             *metadata.GroupProto
	policyData            *atomic.Value // *metadata.Policy
	vTapIPs               *atomic.Value // []*trident.VtapIp
	podIPs                *atomic.Value // []*trident.PodIp
	universalTagNames     *trident.UniversalTagNameMapsResponse
	chPlatformDataChanged chan struct{}
	chGroupDataChanged    chan struct{}
	chPolicyDataChanged   chan struct{}

	isReady atomicbool.Bool // 缓存是否初始化完成

	ctx    context.Context
	cancel context.CancelFunc
}

var trisolarisManager *TrisolarisManager

func IsTheDataReady() bool {
	if trisolarisManager == nil {
		return false
	}
	return trisolarisManager.isReady.IsSet()
}

func GetMetaData() *metadata.MetaData {
	trisolaris := GetTrisolaris(DEFAULT_ORG_ID)
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

func GetGVTapInfo(orgID int) *vtap.VTapInfo {
	if trisolarisManager == nil {
		return nil
	}
	return trisolarisManager.GetVTapInfo(orgID)
}

func GetGNodeInfo() *node.NodeInfo {
	trisolaris := GetTrisolaris(DEFAULT_ORG_ID)
	if trisolaris == nil {
		return nil
	}
	return trisolaris.nodeInfo
}

func TeamIDToTrisolaris(teamID string) *Trisolaris {
	if trisolarisManager == nil {
		return nil
	}
	return trisolarisManager.orgToTrisolaris[GetOrgIDByTeamID(teamID)]
}

func GetGKubernetesInfo(teamID string) *kubernetes.KubernetesInfo {
	tri := TeamIDToTrisolaris(teamID)
	if tri == nil {
		return nil
	}
	return tri.kubernetesInfo
}

func GetConfig() *config.Config {
	return trisolarisManager.config
}

func GetDB() *gorm.DB {
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

func GetTrisolaris(orgID int) *Trisolaris {
	if trisolarisManager == nil {
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

func NewTrisolaris(cfg *config.Config, mDB *mysql.DB, pctx context.Context, startTime int64) *Trisolaris {
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
		platformData := &atomic.Value{}
		platformData.Store(metadata.NewPlatformData("", "", 0, 0))
		policyData := &atomic.Value{}
		policyData.Store(metadata.NewPolicy(-2, "", 0))
		trisolarisManager = &TrisolarisManager{
			orgToTrisolaris:       [utils.ORG_ID_INDEX_MAX]*Trisolaris{},
			refreshOP:             refresh.NewRefreshOP(db, cfg.NodeIP),
			teamIDToOrgID:         make(map[string]int),
			teamIDStrToInt:        make(map[string]int),
			config:                cfg,
			defaultDB:             db,
			platformData:          platformData,
			groupData:             metadata.NewGroupProto(0, 0),
			policyData:            policyData,
			vTapIPs:               &atomic.Value{},
			podIPs:                &atomic.Value{},
			universalTagNames:     &trident.UniversalTagNameMapsResponse{},
			isReady:               atomicbool.NewBool(false),
			chPlatformDataChanged: make(chan struct{}, 1),
			chGroupDataChanged:    make(chan struct{}, 1),
			chPolicyDataChanged:   make(chan struct{}, 1),

			ctx:    ctx,
			cancel: cancel,
		}
	}

	return trisolarisManager
}

func (m *TrisolarisManager) Start() error {
	go m.TimedCheckORG()
	go m.refreshOP.TimedRefreshIPs()
	m.startTime = getStartTime()
	m.groupData.SetStartTime(m.startTime)
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("get orgIDs : %v", orgIDs)
	trisolaris := NewTrisolaris(m.config, mysql.DefaultDB, m.ctx, m.startTime)
	m.RegisterIngesterDataChangedNotify(trisolaris)
	trisolaris.Start()
	m.orgToTrisolaris[DEFAULT_ORG_ID] = trisolaris
	for _, orgID := range orgIDs {
		if utils.CheckOrgID(orgID) == false || orgID == DEFAULT_ORG_ID {
			continue
		}
		orgDB, err := mysql.GetDB(orgID)
		if err != nil {
			log.Error(err)
			continue
		}
		trisolaris := NewTrisolaris(m.config, orgDB, m.ctx, m.startTime)
		m.RegisterIngesterDataChangedNotify(trisolaris)
		trisolaris.Start()
		m.orgToTrisolaris[orgID] = trisolaris
	}

	m.getTeamData(orgIDs)
	go m.TimedGenerateTSDBData()
	log.Infof("finish orgdata init %v", orgIDs)
	m.isReady.Set()
	return nil
}

func (m *TrisolarisManager) NotifyPlatformDataChanged() {
	if m == nil {
		return
	}
	select {
	case m.chPlatformDataChanged <- struct{}{}:
	default:
	}
}

func (m *TrisolarisManager) NotifyGroupDataChanged() {
	if m == nil {
		return
	}
	select {
	case m.chGroupDataChanged <- struct{}{}:
	default:
	}
}

func (m *TrisolarisManager) NotifyPolicyDataChanged() {
	if m == nil {
		return
	}
	select {
	case m.chPolicyDataChanged <- struct{}{}:
	default:
	}
}

func (m *TrisolarisManager) RegisterIngesterDataChangedNotify(trisolaris *Trisolaris) {
	trisolaris.metaData.GetPlatformDataOP().RegisteNotifyIngesterDatachanged(trisolaris.nodeInfo.NotifyBasePlatformDataChanged)
	trisolaris.nodeInfo.RegisteNotifyPlatformDataChanged(m.NotifyPlatformDataChanged)
	trisolaris.metaData.GetPolicyDataOP().RegisteNotifyIngesterDatachanged(m.NotifyPolicyDataChanged)
	trisolaris.metaData.GetGroupDataOP().RegisteNotifyIngesterDatachanged(m.NotifyGroupDataChanged)
}

func (m *TrisolarisManager) getTeamData(orgIDs []int) {
	teamIDToOrgID := make(map[string]int)
	teamIDStrToInt := make(map[string]int)
	for _, orgID := range orgIDs {
		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Error(err)
			continue
		}
		teams, err := dbmgr.DBMgr[mysql.Team](db.DB).Gets()
		if err != nil {
			log.Errorf("get org(id=%d) team failed, err(%s)", orgID, err)
			continue
		}
		for _, team := range teams {
			teamIDToOrgID[team.ShortLcuuid] = team.ORGID
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
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
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
				orgDB, err := mysql.GetDB(orgID)
				if err != nil {
					log.Error(err)
					continue
				}
				trisolaris := NewTrisolaris(m.config, orgDB, m.ctx, m.startTime)
				m.RegisterIngesterDataChangedNotify(trisolaris)
				trisolaris.Start()
				m.orgToTrisolaris[orgID] = trisolaris
			}
		}
	}
	m.getTeamData(orgIDs)
}

func (m *TrisolarisManager) TimedCheckORG() {
	interval := time.Duration(60)
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

func GetIngesterPlatformDataVersion() uint64 {
	return trisolarisManager.getIngesterPlatformDataVersion()
}

func GetIngesterPlatformDataStr() []byte {
	return trisolarisManager.getIngesterPlatformDataStr()
}

func GetIngesterGroupProtoVersion() uint64 {
	return trisolarisManager.getIngesterGroupProtoVersion()
}

func GetIngesterGroupProtoStr() []byte {
	return trisolarisManager.getIngesterGroupProtoStr()
}

func GetIngesterPolicyVersion() uint64 {
	return trisolarisManager.getIngesterPolicyDataVersion()
}

func GetIngesterPolicyStr() []byte {
	return trisolarisManager.getIngesterPolicyDataStr()
}

func GetIngesterVTapIPs() []*trident.VtapIp {
	return trisolarisManager.getIngesterVTtridentPs()
}

func GetIngesterPodIPs() []*trident.PodIp {
	return trisolarisManager.getIngesterPodIPs()
}

func GetIngesterUniversalTagNames() *trident.UniversalTagNameMapsResponse {
	return trisolarisManager.getIngesterUniversalTagNames()
}

func (m *TrisolarisManager) getIngesterPlatformData() *metadata.PlatformData {
	return m.platformData.Load().(*metadata.PlatformData)
}

func (m *TrisolarisManager) updateIngesterPlatformData(data *metadata.PlatformData) {
	m.platformData.Store(data)
}

func (m *TrisolarisManager) getIngesterPolicyata() *metadata.Policy {
	return m.policyData.Load().(*metadata.Policy)
}

func (m *TrisolarisManager) updateIngesterPolicyData(data *metadata.Policy) {
	m.policyData.Store(data)
}

func (m *TrisolarisManager) getIngesterPlatformDataVersion() uint64 {
	return m.getIngesterPlatformData().GetPlatformDataVersion()
}

func (m *TrisolarisManager) getIngesterPlatformDataStr() []byte {
	return m.getIngesterPlatformData().GetPlatformDataStr()
}

func (m *TrisolarisManager) getIngesterGroupProtoVersion() uint64 {
	return m.groupData.GetVersion()
}

func (m *TrisolarisManager) getIngesterGroupProtoStr() []byte {
	return m.groupData.GetGroups()
}

func (m *TrisolarisManager) getIngesterPolicyDataVersion() uint64 {
	return m.getIngesterPolicyata().GetAllVersion()
}

func (m *TrisolarisManager) getIngesterPolicyDataStr() []byte {
	return m.getIngesterPolicyata().GetAllSerializeString()
}

func (m *TrisolarisManager) getIngesterVTtridentPs() []*trident.VtapIp {
	if m == nil {
		return nil
	}
	result, ok := m.vTapIPs.Load().([]*trident.VtapIp)
	if ok {
		return result
	}
	return nil
}

func (m *TrisolarisManager) updateIngesterVTtridentPs(data []*trident.VtapIp) {
	m.vTapIPs.Store(data)
}

func (m *TrisolarisManager) getIngesterPodIPs() []*trident.PodIp {
	if m == nil {
		return nil
	}
	result, ok := m.podIPs.Load().([]*trident.PodIp)
	if ok {
		return result
	}
	return nil
}

func (m *TrisolarisManager) getIngesterUniversalTagNames() *trident.UniversalTagNameMapsResponse {
	if m == nil {
		return nil
	}
	return m.universalTagNames
}

func (m *TrisolarisManager) updateIngesterPodIPs(data []*trident.PodIp) {
	m.podIPs.Store(data)
}

func (m *TrisolarisManager) updateUniversalTagNames(data *trident.UniversalTagNameMapsResponse) {
	m.universalTagNames = data
}

func (m *TrisolarisManager) generateUniversalTagNameMaps(dbCache *metadata.DBDataCache) *trident.UniversalTagNameMapsResponse {
	resp := &trident.UniversalTagNameMapsResponse{
		DeviceMap:      make([]*trident.DeviceMap, len(dbCache.GetChDevicesIDTypeAndName())),
		PodK8SLabelMap: make([]*trident.PodK8SLabelMap, len(dbCache.GetPods())),
		PodMap:         make([]*trident.IdNameMap, len(dbCache.GetPods())),
		RegionMap:      make([]*trident.IdNameMap, len(dbCache.GetRegions())),
		AzMap:          make([]*trident.IdNameMap, len(dbCache.GetAZs())),
		PodNodeMap:     make([]*trident.IdNameMap, len(dbCache.GetPodNodes())),
		PodNsMap:       make([]*trident.IdNameMap, len(dbCache.GetPodNSsIDAndName())),
		PodGroupMap:    make([]*trident.IdNameMap, len(dbCache.GetPodGroups())),
		PodClusterMap:  make([]*trident.IdNameMap, len(dbCache.GetPodClusters())),
		L3EpcMap:       make([]*trident.IdNameMap, len(dbCache.GetVPCs())),
		SubnetMap:      make([]*trident.IdNameMap, len(dbCache.GetSubnets())),
		GprocessMap:    make([]*trident.IdNameMap, len(dbCache.GetProcesses())),
		VtapMap:        make([]*trident.IdNameMap, len(dbCache.GetVTapsIDAndName())),
	}
	for i, pod := range dbCache.GetPods() {
		var labelName, labelValue []string
		for _, label := range strings.Split(pod.Label, ", ") {
			if value := strings.Split(label, ":"); len(value) > 1 {
				labelName = append(labelName, value[0])
				labelValue = append(labelValue, value[1])
			}
		}
		resp.PodK8SLabelMap[i] = &trident.PodK8SLabelMap{
			PodId:      proto.Uint32(uint32(pod.ID)),
			LabelName:  labelName,
			LabelValue: labelValue,
		}
		resp.PodMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(pod.ID)),
			Name: proto.String(pod.Name),
		}
	}
	for i, region := range dbCache.GetRegions() {
		resp.RegionMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(region.ID)),
			Name: proto.String(region.Name),
		}
	}
	for i, az := range dbCache.GetAZs() {
		resp.AzMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(az.ID)),
			Name: proto.String(az.Name),
		}
	}
	for i, podNode := range dbCache.GetPodNodes() {
		resp.PodNodeMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(podNode.ID)),
			Name: proto.String(podNode.Name),
		}
	}
	for i, podNS := range dbCache.GetPodNSsIDAndName() {
		resp.PodNsMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(podNS.ID)),
			Name: proto.String(podNS.Name),
		}
	}
	for i, podGroup := range dbCache.GetPodGroups() {
		resp.PodGroupMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(podGroup.ID)),
			Name: proto.String(podGroup.Name),
		}
	}
	for i, podCluster := range dbCache.GetPodClusters() {
		resp.PodClusterMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(podCluster.ID)),
			Name: proto.String(podCluster.Name),
		}
	}
	for i, vpc := range dbCache.GetVPCs() {
		resp.L3EpcMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(vpc.ID)),
			Name: proto.String(vpc.Name),
		}
	}
	for i, subnet := range dbCache.GetSubnets() {
		resp.SubnetMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(subnet.ID)),
			Name: proto.String(subnet.Name),
		}
	}
	for i, process := range dbCache.GetProcesses() {
		resp.GprocessMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(process.ID)),
			Name: proto.String(process.Name),
		}
	}
	for i, vtap := range dbCache.GetVTapsIDAndName() {
		resp.VtapMap[i] = &trident.IdNameMap{
			Id:   proto.Uint32(uint32(vtap.ID)),
			Name: proto.String(vtap.Name),
		}
	}
	for i, chDevice := range dbCache.GetChDevicesIDTypeAndName() {
		resp.DeviceMap[i] = &trident.DeviceMap{
			Id:   proto.Uint32(uint32(chDevice.DeviceID)),
			Type: proto.Uint32(uint32(chDevice.DeviceType)),
			Name: proto.String(chDevice.Name),
		}
	}

	return resp
}

func MerageData(first *trident.UniversalTagNameMapsResponse, other *trident.UniversalTagNameMapsResponse) {
	first.DeviceMap = utils.Concat(first.DeviceMap, other.DeviceMap)
	first.PodK8SLabelMap = utils.Concat(first.PodK8SLabelMap, other.PodK8SLabelMap)
	first.PodMap = utils.Concat(first.PodMap, other.PodMap)
	first.RegionMap = utils.Concat(first.RegionMap, other.RegionMap)
	first.AzMap = utils.Concat(first.AzMap, other.AzMap)
	first.PodNodeMap = utils.Concat(first.PodNodeMap, other.PodNodeMap)
	first.PodNsMap = utils.Concat(first.PodNsMap, other.PodNsMap)
	first.PodGroupMap = utils.Concat(first.PodGroupMap, other.PodGroupMap)
	first.PodClusterMap = utils.Concat(first.PodClusterMap, other.PodClusterMap)
	first.L3EpcMap = utils.Concat(first.L3EpcMap, other.L3EpcMap)
	first.SubnetMap = utils.Concat(first.SubnetMap, other.SubnetMap)
	first.GprocessMap = utils.Concat(first.GprocessMap, other.GprocessMap)
	first.VtapMap = utils.Concat(first.VtapMap, other.VtapMap)
}

func (m *TrisolarisManager) generateTSDBData() {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
	}

	platformData := metadata.NewPlatformData("platformData", "", 0, PLATFORM_DATA_FOR_INGESTER_MERGE)
	groupData := metadata.NewGroupData(nil, nil)
	policyData := metadata.NewPolicy(-2, "", 0)
	vTapIPs := []*trident.VtapIp{}
	podIPs := []*trident.PodIp{}
	universalTagNames := &trident.UniversalTagNameMapsResponse{}
	for _, orgID := range orgIDs {
		if utils.CheckOrgID(orgID) == false {
			continue
		}
		trisolaris := m.orgToTrisolaris[orgID]
		if trisolaris == nil {
			log.Warningf("orgID(%d) not trisolaris data", orgID)
			continue
		}
		orgPlatformData := trisolaris.nodeInfo.GetPlatformData()
		if orgPlatformData != nil {
			platformData.Merge(orgPlatformData)
		}
		orgGroupData := trisolaris.metaData.GetGroupDataOP().GetDropletGroupsData()
		if orgGroupData != nil {
			groupData.Merge(orgGroupData)
		}
		orgPolicyData := trisolaris.metaData.GetPolicyDataOP().GetDropletPolicy()
		policyData.MergeIngesterPolicy(orgPolicyData)
		vTapIPs = append(vTapIPs, trisolaris.vTapInfo.GetVTapIPs()...)
		podIPs = append(podIPs, trisolaris.metaData.GetPlatformDataOP().GetPodIPs()...)

		orgUniversalTagNameDatga := m.generateUniversalTagNameMaps(trisolaris.metaData.GetDBDataCache())
		MerageData(universalTagNames, orgUniversalTagNameDatga)

	}
	platformData.GeneratePlatformDataResult()
	m.updateIngesterPlatformData(platformData)
	m.groupData.GenerateIngesterGroup(groupData)
	policyData.GenerateIngesterData()
	m.updateIngesterPolicyData(policyData)
	m.updateIngesterVTtridentPs(vTapIPs)
	m.updateIngesterPodIPs(podIPs)
	m.updateUniversalTagNames(universalTagNames)
}

func (m *TrisolarisManager) generateIngesterPlatformData() {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
	}

	platformData := metadata.NewPlatformData("platformData", "", 0, PLATFORM_DATA_FOR_INGESTER_MERGE)
	for _, orgID := range orgIDs {
		if utils.CheckOrgID(orgID) == false {
			continue
		}
		trisolaris := m.orgToTrisolaris[orgID]
		if trisolaris == nil {
			log.Warningf("orgID(%d) not trisolaris data", orgID)
			continue
		}
		orgPlatformData := trisolaris.nodeInfo.GetPlatformData()
		if orgPlatformData != nil {
			platformData.Merge(orgPlatformData)
		}
	}
	platformData.GeneratePlatformDataResult()
	m.updateIngesterPlatformData(platformData)
}

func (m *TrisolarisManager) generateIngesterGroupData() {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
	}

	groupData := metadata.NewGroupData(nil, nil)
	for _, orgID := range orgIDs {
		if utils.CheckOrgID(orgID) == false {
			continue
		}
		trisolaris := m.orgToTrisolaris[orgID]
		if trisolaris == nil {
			log.Warningf("orgID(%d) not trisolaris data", orgID)
			continue
		}
		orgGroupData := trisolaris.metaData.GetGroupDataOP().GetDropletGroupsData()
		if orgGroupData != nil {
			groupData.Merge(orgGroupData)
		}

	}
	m.groupData.GenerateIngesterGroup(groupData)
}

func (m *TrisolarisManager) generateIngesterPolicyData() {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error(err)
		return
	}

	policyData := metadata.NewPolicy(-2, "", 0)
	for _, orgID := range orgIDs {
		if utils.CheckOrgID(orgID) == false {
			continue
		}
		trisolaris := m.orgToTrisolaris[orgID]
		if trisolaris == nil {
			log.Warningf("orgID(%d) not trisolaris data", orgID)
			continue
		}
		orgPolicyData := trisolaris.metaData.GetPolicyDataOP().GetDropletPolicy()
		policyData.MergeIngesterPolicy(orgPolicyData)
	}
	policyData.GenerateIngesterData()
	m.updateIngesterPolicyData(policyData)
}

func (m *TrisolarisManager) TimedGenerateTSDBData() {
	m.generateTSDBData()
	interval := time.Duration(60)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate ingester data from timed")
			m.generateTSDBData()
			log.Info("end generate ingester data from timed")
		case <-m.chPlatformDataChanged:
			log.Info("pltformdata changed start generate ingester pltformdata")
			m.generateIngesterPlatformData()
			pushmanager.IngesterBroadcast()
		case <-m.chGroupDataChanged:
			log.Info("groupdata changed start generate ingester groupdata")
			m.generateIngesterGroupData()
			pushmanager.IngesterBroadcast()
		case <-m.chPolicyDataChanged:
			log.Info("policydata changed start generate ingester policydata")
			m.generateIngesterPolicyData()
			pushmanager.IngesterBroadcast()
		}
	}
}
