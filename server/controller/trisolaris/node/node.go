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

package node

import (
	"errors"
	"strconv"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"
	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/message/trident"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/service"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/pushmanager"
)

var log = logging.MustGetLogger("trisolaris/node")

type NodeInfo struct {
	tsdbCaches              *TSDBCacheMap // 数据节点缓存
	tsdbRegion              map[string]uint32
	tsdbToNATIP             map[string]string
	tsdbToPodIP             map[string]string
	controllerToNATIP       map[string]string
	controllerToPodIP       map[string]string
	sysConfigurationToValue map[string]string
	pcapDataRetention       uint32
	metaData                *metadata.MetaData
	tsdbRegister            *TSDBDiscovery
	controllerRegister      *ControllerDiscovery
	chRegister              chan struct{} // 数据节点注册通知channel
	config                  *config.Config
	chNodeInfo              chan struct{} // node变化通知channel
	groups                  []byte        // 数据节点资源组信息
	groupHash               uint64        // 资源组数据hash值
	db                      *gorm.DB
}

func NewNodeInfo(db *gorm.DB, metaData *metadata.MetaData, cfg *config.Config) *NodeInfo {
	return &NodeInfo{
		tsdbCaches:              newTSDBCacheMap(),
		tsdbRegion:              make(map[string]uint32),
		tsdbToNATIP:             make(map[string]string),
		tsdbToPodIP:             make(map[string]string),
		controllerToNATIP:       make(map[string]string),
		controllerToPodIP:       make(map[string]string),
		sysConfigurationToValue: make(map[string]string),
		metaData:                metaData,
		tsdbRegister:            newTSDBDiscovery(),
		controllerRegister:      newControllerDiscovery(cfg.NodeIP, cfg.NodeType, cfg.RegionDomainPrefix),
		chRegister:              make(chan struct{}, 1),
		config:                  cfg,
		chNodeInfo:              make(chan struct{}, 1),
		db:                      db,
	}
}

func (n *NodeInfo) GetTSDBCache(key string) *TSDBCache {
	return n.tsdbCaches.Get(key)
}

func (n *NodeInfo) GetPlatformDataVersion() uint64 {
	return n.metaData.GetPlatformDataOP().GetDropletPlatforDataVersion()
}

func (n *NodeInfo) GetPlatformDataStr() []byte {
	return n.metaData.GetPlatformDataOP().GetDropletPlatforDataStr()
}

func (n *NodeInfo) GetPodIPs() []*trident.PodIp {
	return n.metaData.GetPlatformDataOP().GetPodIPs()
}

func (n *NodeInfo) updateTSDBSyncedToDB() {
	log.Info("update tsdb info to db")
	dbTSDBs, err := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	if err != nil || len(dbTSDBs) == 0 {
		log.Error(err)
		return
	}
	keytoDB := make(map[string]*models.Analyzer)
	for _, dbTSDB := range dbTSDBs {
		keytoDB[dbTSDB.IP] = dbTSDB
	}
	updateTSDB := make([]*models.Analyzer, 0, len(dbTSDBs))
	cacheKeys := n.tsdbCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheTSDB := n.GetTSDBCache(cacheKey)
		if cacheTSDB == nil {
			continue
		}
		dbTSDB, ok := keytoDB[cacheKey]
		if ok == false {
			continue
		}
		if !cacheTSDB.syncFlag.IsSet() {
			continue
		}
		cacheSyncedAt := cacheTSDB.GetSyncedAt()
		if cacheSyncedAt != nil && !dbTSDB.SyncedAt.Equal(*cacheSyncedAt) {
			dbTSDB.SyncedAt = *cacheSyncedAt
		}
		filter := false
		if dbTSDB.CPUNum != cacheTSDB.cpuNum {
			dbTSDB.CPUNum = cacheTSDB.cpuNum
			filter = true
		}
		if dbTSDB.MemorySize != cacheTSDB.memorySize {
			dbTSDB.MemorySize = cacheTSDB.memorySize
			filter = true
		}
		if dbTSDB.MemorySize != cacheTSDB.memorySize {
			dbTSDB.MemorySize = cacheTSDB.memorySize
			filter = true
		}
		if dbTSDB.Arch != cacheTSDB.GetArch() {
			dbTSDB.Arch = cacheTSDB.GetArch()
			filter = true
		}
		if dbTSDB.Os != cacheTSDB.GetOS() {
			dbTSDB.Os = cacheTSDB.GetOS()
			filter = true
		}
		if dbTSDB.KernelVersion != cacheTSDB.GetKernelVersion() {
			dbTSDB.KernelVersion = cacheTSDB.GetKernelVersion()
			filter = true
		}
		if dbTSDB.PcapDataMountPath != cacheTSDB.GetPcapDataMountPath() {
			dbTSDB.PcapDataMountPath = cacheTSDB.GetPcapDataMountPath()
			filter = true
		}
		if cacheTSDB.GetName() != "" && dbTSDB.Name != cacheTSDB.GetName() {
			dbTSDB.Name = cacheTSDB.GetName()
			filter = true
		}
		if dbTSDB.PodIP != cacheTSDB.GetPodIP() {
			dbTSDB.PodIP = cacheTSDB.GetPodIP()
			filter = true
		}
		if filter == true {
			updateTSDB = append(updateTSDB, dbTSDB)
		}
		cacheTSDB.unsetSyncFlag()
	}

	if len(updateTSDB) > 0 {
		mgr := dbmgr.DBMgr[models.Analyzer](n.db)
		err := mgr.UpdateBulk(updateTSDB)
		if err != nil {
			log.Error(err)
		}
	}
}

func (n *NodeInfo) AddTSDBCache(tsdb *models.Analyzer) {
	tsdbCache := newTSDBCache(tsdb)
	n.tsdbCaches.Add(tsdbCache)

	log.Infof("add tsdb cache %s", tsdb.IP)
}

func (n *NodeInfo) DeleteTSDBCache(key string) {
	log.Info("delete tsdb cache", key)
	n.tsdbCaches.Delete(key)
}

func (n *NodeInfo) generateControllerInfo() {
	dbControllers, err := dbmgr.DBMgr[models.Controller](n.db).Gets()
	if err != nil {
		log.Error(err)
		return
	}
	if len(dbControllers) == 0 {
		return
	}

	controllerToNATIP := make(map[string]string)
	controllerToPodIP := make(map[string]string)
	for _, controller := range dbControllers {
		controllerToNATIP[controller.IP] = controller.NATIP
		controllerToPodIP[controller.IP] = controller.PodIP
	}
	n.controllerToNATIP = controllerToNATIP
	n.controllerToPodIP = controllerToPodIP
}

func (n *NodeInfo) initTSDBInfo() {
	dbTSDBs, err := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	if err != nil {
		log.Error(err)
		return
	}
	if len(dbTSDBs) == 0 {
		return
	}

	tsdbToNATIP := make(map[string]string)
	tsdbToPodIP := make(map[string]string)
	for _, dbTSDB := range dbTSDBs {
		n.AddTSDBCache(dbTSDB)
		tsdbToNATIP[dbTSDB.IP] = dbTSDB.NATIP
		tsdbToPodIP[dbTSDB.IP] = dbTSDB.PodIP
	}
	n.tsdbToNATIP = tsdbToNATIP
	n.tsdbToPodIP = tsdbToPodIP
	n.generateTSDBRegion()
	n.generatesysConfiguration()
}

func (n *NodeInfo) generateTSDBRegion() {
	dbAZTSDBConns, _ := dbmgr.DBMgr[models.AZAnalyzerConnection](n.db).Gets()
	dbRegions, _ := dbmgr.DBMgr[models.Region](n.db).Gets()
	lcuuidToRegionID := make(map[string]int)
	ipToRegionID := make(map[string]uint32)
	for _, region := range dbRegions {
		lcuuidToRegionID[region.Lcuuid] = region.ID
	}
	for _, azConn := range dbAZTSDBConns {
		if regionID, ok := lcuuidToRegionID[azConn.Region]; ok {
			ipToRegionID[azConn.AnalyzerIP] = uint32(regionID)
		}
	}
	n.tsdbRegion = ipToRegionID
}

func (n *NodeInfo) generatesysConfiguration() {
	dbSysConfigurations, _ := dbmgr.DBMgr[models.SysConfiguration](n.db).Gets()
	sysConfigurationToValue := make(map[string]string)
	if dbSysConfigurations != nil {
		for _, sysConfig := range dbSysConfigurations {
			sysConfigurationToValue[sysConfig.ParamName] = sysConfig.Value
		}
	}
	n.sysConfigurationToValue = sysConfigurationToValue

	pcapDataRetention := n.sysConfigurationToValue["pcap_data_retention"]
	if pcapDataRetention != "" {
		pcapDataRetentionInt, err := strconv.Atoi(pcapDataRetention)
		if err == nil {
			n.pcapDataRetention = uint32(pcapDataRetentionInt)
		}
	}
}

func (n *NodeInfo) GetPcapDataRetention() uint32 {
	return n.pcapDataRetention
}

func (n *NodeInfo) GetRegionIDByTSDBIP(tsdbIP string) uint32 {
	return n.tsdbRegion[tsdbIP]
}

func (n *NodeInfo) updateTSDBCache(key string, tsdb *models.Analyzer) {
	cacheTSDB := n.GetTSDBCache(key)
	if cacheTSDB == nil {
		return
	}

	cacheTSDB.updateNatIP(tsdb.NATIP)
}

func (n *NodeInfo) updateTSDBNATIP(data map[string]string) {
	n.tsdbToNATIP = data
}

func (n *NodeInfo) GetTSDBNatIP(ip string) string {
	return n.tsdbToNATIP[ip]
}

func (n *NodeInfo) updateTSDBPodIP(data map[string]string) {
	n.tsdbToPodIP = data
}

func (n *NodeInfo) GetTSDBPodIP(ip string) string {
	return n.tsdbToPodIP[ip]
}

func (n *NodeInfo) GetControllerNatIP(ip string) string {
	return n.controllerToNATIP[ip]
}

func (n *NodeInfo) GetControllerPodIP(ip string) string {
	return n.controllerToPodIP[ip]
}

func (n *NodeInfo) updateTSDBInfo() {
	n.generateTSDBRegion()
	n.generatesysConfiguration()
	dbTSDBs, _ := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	dbKeys := mapset.NewSet()
	ipToTSDB := make(map[string]*models.Analyzer)
	tsdbToNATIP := make(map[string]string)
	tsdbToPodIP := make(map[string]string)
	for _, dbTSDB := range dbTSDBs {
		ipToTSDB[dbTSDB.IP] = dbTSDB
		tsdbToNATIP[dbTSDB.IP] = dbTSDB.NATIP
		tsdbToPodIP[dbTSDB.IP] = dbTSDB.PodIP
		dbKeys.Add(dbTSDB.IP)
	}
	n.updateTSDBNATIP(tsdbToNATIP)
	n.updateTSDBPodIP(tsdbToPodIP)

	cacheKeys := n.tsdbCaches.GetKeySet()
	addTSDB := dbKeys.Difference(cacheKeys)
	delTSDB := cacheKeys.Difference(dbKeys)
	updateTSDB := dbKeys.Intersect(cacheKeys)
	for val := range addTSDB.Iter() {
		dbTSDB, ok := ipToTSDB[val.(string)]
		if ok {
			n.AddTSDBCache(dbTSDB)
		}
	}

	for val := range delTSDB.Iter() {
		n.DeleteTSDBCache(val.(string))
	}

	for val := range updateTSDB.Iter() {
		vtap, ok := ipToTSDB[val.(string)]
		if ok {
			n.updateTSDBCache(val.(string), vtap)
		}
	}
}

func (n *NodeInfo) generateTSDBCache() {
	n.updateTSDBInfo()
	n.updateTSDBSyncedToDB()
}

func (n *NodeInfo) generateNodeCache() {
	n.generateTSDBCache()
	n.generateControllerInfo()
}

func (n *NodeInfo) registerTSDBToDB(tsdb *models.Analyzer) {
	tsdbMgr := dbmgr.DBMgr[models.Analyzer](n.db)
	option := tsdbMgr.WithIP(tsdb.IP)
	_, err := tsdbMgr.GetByOption(option)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = tsdbMgr.Insert(tsdb)
		if err != nil {
			log.Error(err)
			return
		}
		n.AddTSDBCache(tsdb)
		azConn := &models.AZAnalyzerConnection{
			AZ:         CONN_DEFAULT_AZ,
			Region:     CONN_DEFAULT_REGION,
			AnalyzerIP: tsdb.IP,
			Lcuuid:     uuid.NewString(),
		}
		err := dbmgr.DBMgr[models.AZAnalyzerConnection](n.db).Insert(azConn)
		if err != nil {
			log.Error(err)
		}
		err = service.ConfigAnalyzerDataSource(tsdb.IP)
		if err != nil {
			log.Error(err)
		}
	} else if err != nil {
		log.Error(err)
	}
}

func (n *NodeInfo) RegisterTSDB(request *trident.SyncRequest) {
	log.Infof("register tsdb(%v)", request)
	n.tsdbRegister.register(request)
	select {
	case n.chRegister <- struct{}{}:
	default:
	}
}

func (n *NodeInfo) isRegisterController() {
	data := n.controllerRegister.GetControllerData()
	if data == nil {
		return
	}
	controllerMgr := dbmgr.DBMgr[models.Controller](n.db)
	option := controllerMgr.WithIP(data.IP)
	dbController, err := controllerMgr.GetByOption(option)
	if err == nil {
		changed := false
		if data.Name != "" && dbController.Name != data.Name {
			dbController.Name = data.Name
			changed = true
		}
		if dbController.CPUNum != data.CPUNum {
			dbController.CPUNum = data.CPUNum
			changed = true
		}
		if dbController.MemorySize != data.MemorySize {
			dbController.MemorySize = data.MemorySize
			changed = true
		}
		if dbController.Arch != data.Arch {
			dbController.Arch = data.Arch
			changed = true
		}
		if dbController.Os != data.Os {
			dbController.Os = data.Os
			changed = true
		}
		if dbController.Os != data.Os {
			dbController.Os = data.Os
			changed = true
		}
		if dbController.KernelVersion != data.KernelVersion {
			dbController.KernelVersion = data.KernelVersion
			changed = true
		}
		if dbController.RegionDomainPrefix != data.RegionDomainPrefix {
			dbController.RegionDomainPrefix = data.RegionDomainPrefix
			changed = true
		}
		if dbController.NodeType != data.NodeType {
			dbController.NodeType = data.NodeType
			changed = true
		}
		if dbController.NodeName != data.NodeName {
			dbController.NodeName = data.NodeName
			changed = true
		}
		if dbController.PodIP != data.PodIP {
			dbController.PodIP = data.PodIP
			changed = true
		}
		if changed {
			controllerMgr.Save(dbController)
		}
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		n.registerControllerToDB(data)
	} else {
		log.Error(err)
	}
}

func (n *NodeInfo) GetGroups() []byte {
	return n.metaData.GetDropletGroups()
}

func (n *NodeInfo) GetGroupsVersion() uint64 {
	return n.metaData.GetDropletGroupsVersion()
}

func (n *NodeInfo) GetPolicy() []byte {
	return n.metaData.GetDropletPolicyStr()
}

func (n *NodeInfo) GetPolicyVersion() uint64 {
	return n.metaData.GetDropletPolicyVersion()
}

func (n *NodeInfo) registerControllerToDB(data *models.Controller) {
	log.Infof("resiter controller(%+v)", data)
	err := dbmgr.DBMgr[models.Controller](n.db).Insert(data)
	if err != nil {
		log.Error(err)
		return
	}
	azConn := &models.AZControllerConnection{
		AZ:           CONN_DEFAULT_AZ,
		Region:       CONN_DEFAULT_REGION,
		ControllerIP: data.IP,
		Lcuuid:       uuid.NewString(),
	}
	err = dbmgr.DBMgr[models.AZControllerConnection](n.db).Insert(azConn)
	if err != nil {
		log.Error(err)
	}
}

func (n *NodeInfo) registerTSDB() {
	log.Info("start register rsdb")
	data := n.tsdbRegister.getRegisterData()
	for _, tsdb := range data {
		n.registerTSDBToDB(tsdb)
	}
	log.Info("end register tsdb")
}

func (n *NodeInfo) PutChNodeInfo() {
	select {
	case n.chNodeInfo <- struct{}{}:
	default:
	}
}

func (n *NodeInfo) startMonitoRegister() {
	for {
		select {
		case <-n.chRegister:
			n.registerTSDB()
		}
	}
}

func (n *NodeInfo) TimedRefreshNodeCache() {
	n.initTSDBInfo()
	n.generateControllerInfo()
	n.isRegisterController()
	go n.startMonitoRegister()
	interval := time.Duration(n.config.NodeRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate node cache data from timed")
			n.isRegisterController()
			n.generateNodeCache()
			log.Info("end generate node cache data from timed")
		case <-n.chNodeInfo:
			log.Info("start generate node cache data from rpc")
			n.generateNodeCache()
			pushmanager.Broadcast()
			log.Info("end generate node cache data from rpc")
		}
	}
}
