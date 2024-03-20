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

package node

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var log = logging.MustGetLogger("trisolaris/node")

type NodeInfo struct {
	tsdbCaches              *TSDBCacheMap // 数据节点缓存
	tsdbRegion              map[string]uint32
	tsdbToNATIP             map[string]string
	tsdbToPodIP             map[string]string
	tsdbToID                map[string]uint32
	controllerToNATIP       map[string]string
	controllerToPodIP       map[string]string
	localServers            *atomic.Value // []*trident.DeepFlowServerInstanceInfo
	platformData            *atomic.Value // *metaData.PlatformData
	localRegion             *string
	localAZs                []string
	sysConfigurationToValue map[string]string
	pcapDataRetention       uint32
	metaData                *metadata.MetaData
	tsdbRegister            *TSDBDiscovery
	controllerRegister      *ControllerDiscovery
	chRegister              chan struct{} // 数据节点注册通知channel
	config                  *config.Config
	chNodeInfo              chan struct{} // node变化通知channel
	db                      *gorm.DB
	ctx                     context.Context
	cancel                  context.CancelFunc

	ORGID
}

func NewNodeInfo(db *gorm.DB, metaData *metadata.MetaData, cfg *config.Config, orgID int, pctx context.Context) *NodeInfo {
	ctx, cancel := context.WithCancel(pctx)
	localServers := &atomic.Value{}
	localServers.Store([]*trident.DeepFlowServerInstanceInfo{})
	platformData := &atomic.Value{}
	platformData.Store(metadata.NewPlatformData("", "", 0, 0))
	nodeInfo := &NodeInfo{
		tsdbCaches:              newTSDBCacheMap(),
		tsdbRegion:              make(map[string]uint32),
		tsdbToNATIP:             make(map[string]string),
		tsdbToPodIP:             make(map[string]string),
		tsdbToID:                make(map[string]uint32),
		controllerToNATIP:       make(map[string]string),
		controllerToPodIP:       make(map[string]string),
		localServers:            localServers,
		platformData:            platformData,
		sysConfigurationToValue: make(map[string]string),
		metaData:                metaData,
		tsdbRegister:            newTSDBDiscovery(),
		controllerRegister:      newControllerDiscovery(cfg.NodeIP, cfg.NodeType, cfg.RegionDomainPrefix, metaData.ORGID),
		chRegister:              make(chan struct{}, 1),
		config:                  cfg,
		chNodeInfo:              make(chan struct{}, 1),
		db:                      db,
		ctx:                     ctx,
		cancel:                  cancel,
		ORGID:                   ORGID(orgID),
	}
	return nodeInfo
}

func (n *NodeInfo) GetTSDBCache(key string) *TSDBCache {
	return n.tsdbCaches.Get(key)
}

func (n *NodeInfo) GetPlatformDataVersion() uint64 {
	return n.getPlatformData().GetPlatformDataVersion()
}

func (n *NodeInfo) GetPlatformDataStr() []byte {
	return n.getPlatformData().GetPlatformDataStr()
}

func (n *NodeInfo) GetPodIPs() []*trident.PodIp {
	return n.metaData.GetPlatformDataOP().GetPodIPs()
}

func (n *NodeInfo) updateTSDBSyncedToDB() {
	log.Info(n.Log("update tsdb info to db"))
	dbTSDBs, err := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	if err != nil || len(dbTSDBs) == 0 {
		log.Error(n.Logf("get analyzer(count=%d) failed  err:%v", len(dbTSDBs), err))
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
		if dbTSDB.PodName != cacheTSDB.GetPodName() {
			dbTSDB.PodName = cacheTSDB.GetPodName()
			filter = true
		}
		if dbTSDB.CAMD5 != GetCAMD5() {
			dbTSDB.CAMD5 = GetCAMD5()
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
			log.Error(n.Log(err.Error()))
		}
	}
}

func (n *NodeInfo) AddTSDBCache(tsdb *models.Analyzer) {
	tsdbCache := newTSDBCache(tsdb)
	n.tsdbCaches.Add(tsdbCache)

	log.Infof(n.Logf("add tsdb cache %s", tsdb.IP))
}

func (n *NodeInfo) DeleteTSDBCache(key string) {
	log.Info(n.Logf("delete tsdb cache %s", key))
	n.tsdbCaches.Delete(key)
}

func (n *NodeInfo) updateLocalRegion(region string) {
	n.localRegion = &region
}

func (n *NodeInfo) getLocalRegion() string {
	if n.localRegion == nil {
		return ""
	}
	return *n.localRegion
}

func (n *NodeInfo) updateLocalAZs(azs []string) {
	n.localAZs = azs
}

func (n *NodeInfo) getLocalAZs() []string {
	return n.localAZs
}

func (n *NodeInfo) generateControllerInfo() {
	dbControllers, err := dbmgr.DBMgr[models.Controller](n.db).Gets()
	if err != nil {
		log.Error(n.Log(err.Error()))
		return
	}
	if len(dbControllers) == 0 {
		return
	}
	localIPs := make(map[string]struct{})
	localConn, err := dbmgr.DBMgr[models.AZControllerConnection](n.db).GetFromControllerIP(n.config.NodeIP)
	if err != nil {
		log.Errorf(n.Logf("find local controller(%s) region failed, err:%s", n.config.NodeIP, err))
	} else {
		n.updateLocalRegion(localConn.Region)
		azControllerconns, err := dbmgr.DBMgr[models.AZControllerConnection](n.db).GetBatchFromRegion(localConn.Region)
		if err == nil {
			for _, conn := range azControllerconns {
				if conn.ControllerIP != "" {
					localIPs[conn.ControllerIP] = struct{}{}
				}
			}
		} else {
			log.Error(n.Log(err.Error()))
		}
	}

	localServers := make([]*trident.DeepFlowServerInstanceInfo, 0, len(dbControllers))
	controllerToNATIP := make(map[string]string)
	controllerToPodIP := make(map[string]string)
	for _, controller := range dbControllers {
		if controller.State != HOST_STATE_EXCEPTION {
			if _, ok := localIPs[controller.IP]; ok {
				server := &trident.DeepFlowServerInstanceInfo{
					PodName:  proto.String(controller.PodName),
					NodeName: proto.String(controller.NodeName),
				}
				localServers = append(localServers, server)
			}
		}
		controllerToNATIP[controller.IP] = controller.NATIP
		controllerToPodIP[controller.IP] = controller.PodIP
	}
	n.controllerToNATIP = controllerToNATIP
	n.controllerToPodIP = controllerToPodIP
	n.updateLocalServers(localServers)

	localConns, err := dbmgr.DBMgr[models.AZControllerConnection](n.db).GetBatchFromControllerIP(n.config.NodeIP)
	if err == nil {
		localAZs := make([]string, 0, len(localConns))
		for _, localConn := range localConns {
			if Contains(localAZs, localConn.AZ) == false {
				localAZs = append(localAZs, localConn.AZ)
			}
		}
		n.updateLocalAZs(localAZs)
	} else {
		log.Error(n.Log(err.Error()))
	}
}

func (n *NodeInfo) correctTSDBPodIP() {
	tsdbMgr := dbmgr.DBMgr[models.Analyzer](n.db)
	tsdb, err := tsdbMgr.GetByOption(tsdbMgr.WithIP(GetNodeIP()))
	if err == nil && tsdb.PodIP != GetPodIP() {
		tsdb.PodIP = GetPodIP()
		tsdbMgr.Save(tsdb)
	}
}

func (n *NodeInfo) initTSDBInfo() {
	// The pod_ip will change after restarting the server, correct the pod_ip
	n.correctTSDBPodIP()
	dbTSDBs, err := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	if err != nil {
		log.Error(n.Log(err.Error()))
		return
	}
	if len(dbTSDBs) == 0 {
		return
	}

	tsdbToNATIP := make(map[string]string)
	tsdbToPodIP := make(map[string]string)
	tsdbToID := make(map[string]uint32)
	for index, dbTSDB := range dbTSDBs {
		n.AddTSDBCache(dbTSDB)
		tsdbToNATIP[dbTSDB.IP] = dbTSDB.NATIP
		tsdbToPodIP[dbTSDB.IP] = dbTSDB.PodIP
		tsdbToID[dbTSDB.IP] = uint32(index + 1)
	}
	n.tsdbToNATIP = tsdbToNATIP
	n.tsdbToPodIP = tsdbToPodIP
	n.tsdbToID = tsdbToID
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

func (n *NodeInfo) updateTSDBToID(data map[string]uint32) {
	n.tsdbToID = data
}

func (n *NodeInfo) GetTSDBID(ip string) uint32 {
	return n.tsdbToID[ip]
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

func (n *NodeInfo) updateLocalServers(servers []*trident.DeepFlowServerInstanceInfo) {
	n.localServers.Store(servers)
}

func (n *NodeInfo) GetLocalControllers() []*trident.DeepFlowServerInstanceInfo {
	return n.localServers.Load().([]*trident.DeepFlowServerInstanceInfo)
}

func (n *NodeInfo) updateTSDBInfo() {
	n.generateTSDBRegion()
	n.generatesysConfiguration()
	dbTSDBs, _ := dbmgr.DBMgr[models.Analyzer](n.db).Gets()
	dbKeys := mapset.NewSet()
	ipToTSDB := make(map[string]*models.Analyzer)
	tsdbToNATIP := make(map[string]string)
	tsdbToPodIP := make(map[string]string)
	tsdbToID := make(map[string]uint32)
	for index, dbTSDB := range dbTSDBs {
		ipToTSDB[dbTSDB.IP] = dbTSDB
		tsdbToNATIP[dbTSDB.IP] = dbTSDB.NATIP
		tsdbToPodIP[dbTSDB.IP] = dbTSDB.PodIP
		tsdbToID[dbTSDB.IP] = uint32(index + 1)
		dbKeys.Add(dbTSDB.IP)
	}
	n.updateTSDBNATIP(tsdbToNATIP)
	n.updateTSDBPodIP(tsdbToPodIP)
	n.updateTSDBToID(tsdbToID)

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

func (n *NodeInfo) generateDataForDefaultORG() {
	n.generateTSDBCache()
	n.generateControllerInfo()
}

func (n *NodeInfo) generateDataForNotDefaultORG() {
	n.updateTSDBInfo()
	n.generateControllerInfo()
}

func (n *NodeInfo) registerTSDBToDB(tsdb *models.Analyzer) {
	tsdbMgr := dbmgr.DBMgr[models.Analyzer](n.db)
	tsdbs, err := tsdbMgr.Gets()
	if err != nil {
		log.Error(n.Log(err.Error()))
		return
	}
	var azConns []*models.AZAnalyzerConnection
	tsdbCount := len(tsdbs)
	option := tsdbMgr.WithIP(tsdb.IP)
	_, err = tsdbMgr.GetByOption(option)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		switch {
		case tsdbCount == 0 || tsdb.CAMD5 == "":
			azConn := &models.AZAnalyzerConnection{
				AZ:         CONN_DEFAULT_AZ,
				Region:     CONN_DEFAULT_REGION,
				AnalyzerIP: tsdb.IP,
				Lcuuid:     uuid.NewString(),
			}
			azConns = append(azConns, azConn)
		case tsdbCount > 0:
			localTSDB, err := tsdbMgr.GetFromCAMD5(tsdb.CAMD5)
			if err == nil {
				conns, err := dbmgr.DBMgr[models.AZAnalyzerConnection](n.db).GetBatchFromAnalyzerIP(localTSDB.IP)
				if err == nil {
					for _, conn := range conns {
						azConn := &models.AZAnalyzerConnection{
							AZ:         conn.AZ,
							Region:     conn.Region,
							AnalyzerIP: tsdb.IP,
							Lcuuid:     uuid.NewString(),
						}
						azConns = append(azConns, azConn)
					}
				} else {
					log.Error(err)
				}
			} else {
				log.Error(n.Log(err.Error()))
			}
		}
		err = tsdbMgr.Insert(tsdb)
		if err != nil {
			log.Error(n.Log(err.Error()))
			return
		}
		n.AddTSDBCache(tsdb)
		if len(azConns) > 0 {
			for _, azConn := range azConns {
				err := dbmgr.DBMgr[models.AZAnalyzerConnection](n.db).Insert(azConn)
				if err != nil {
					log.Error(n.Log(err.Error()))
				}
			}
		}

		if IsStandaloneRunningMode() {
			// in standalone mode, since all in one deployment and analyzer communication use 127.0.0.1
			err = service.ConfigAnalyzerDataSource("127.0.0.1")
		} else {
			err = service.ConfigAnalyzerDataSource(tsdb.IP)
		}

		if err != nil {
			log.Error(n.Log(err.Error()))
		}
	} else if err != nil {
		log.Error(n.Log(err.Error()))
	}
}

func (n *NodeInfo) RegisterTSDB(request *trident.SyncRequest) {
	log.Infof(n.Logf("register tsdb(%v)", request))
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
		if dbController.PodName != data.PodName {
			dbController.PodName = data.PodName
			changed = true
		}
		if dbController.PodIP != data.PodIP {
			dbController.PodIP = data.PodIP
			changed = true
		}
		if dbController.PodName != data.PodName {
			dbController.PodName = data.PodName
			changed = true
		}
		if dbController.CAMD5 != data.CAMD5 {
			dbController.CAMD5 = data.CAMD5
			changed = true
		}
		if changed {
			controllerMgr.Save(dbController)
		}
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		n.registerControllerToDB(data)
	} else {
		log.Error(n.Log(err.Error()))
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
	log.Infof(n.Logf("resiter controller(%+v)", data))
	controllerDBMgr := dbmgr.DBMgr[models.Controller](n.db)
	controllers, err := controllerDBMgr.Gets()
	if err != nil {
		log.Error(n.Log(err.Error()))
		return
	}
	controllerCount := len(controllers)
	var azConns []*models.AZControllerConnection

	switch {
	case controllerCount == 0 || data.CAMD5 == "":
		azConn := &models.AZControllerConnection{
			AZ:           CONN_DEFAULT_AZ,
			Region:       CONN_DEFAULT_REGION,
			ControllerIP: data.IP,
			Lcuuid:       uuid.NewString(),
		}
		azConns = append(azConns, azConn)
	case controllerCount > 0:
		localController, err := controllerDBMgr.GetFromCAMD5(data.CAMD5)
		if err == nil {
			conns, err := dbmgr.DBMgr[models.AZControllerConnection](n.db).GetBatchFromControllerIP(localController.IP)
			if err == nil {
				for _, conn := range conns {
					azConn := &models.AZControllerConnection{
						AZ:           conn.AZ,
						Region:       conn.Region,
						ControllerIP: data.IP,
						Lcuuid:       uuid.NewString(),
					}
					azConns = append(azConns, azConn)
				}
			} else {
				log.Error(n.Log(err.Error()))
			}
		} else {
			log.Error(n.Log(err.Error()))
		}
	}
	err = controllerDBMgr.Insert(data)
	if err != nil {
		log.Error(n.Log(err.Error()))
		return
	}
	if len(azConns) != 0 {
		connDBMgr := dbmgr.DBMgr[models.AZControllerConnection](n.db)
		for _, azConn := range azConns {
			err := connDBMgr.Insert(azConn)
			if err != nil {
				log.Error(n.Log(err.Error()))
			}
		}
	}
}

func (n *NodeInfo) getPlatformData() *metadata.PlatformData {
	return n.platformData.Load().(*metadata.PlatformData)
}

func (n *NodeInfo) updatePlatformData(data *metadata.PlatformData) {
	n.platformData.Store(data)
}

func (n *NodeInfo) getPodClusterInternalIPToIngester() int {
	return n.config.PodClusterInternalIPToIngester
}

func (n *NodeInfo) generatePlatformData() {
	podClusterInternalIPToIngester := n.getPodClusterInternalIPToIngester()
	localRegion := n.getLocalRegion()
	localAZs := n.getLocalAZs()
	log.Infof(n.Logf("generate ingester platform data (region=%s azs=%s podClusterInternalIPToIngester=%d)", n.getLocalRegion(), n.getLocalAZs(), podClusterInternalIPToIngester))
	switch podClusterInternalIPToIngester {
	case ALL_K8S_CLUSTER:
		n.updatePlatformData(n.metaData.GetPlatformDataOP().GetAllPlatformDataForIngester())
	case K8S_CLUSTER_IN_LOCAL_REGION:
		allCompletePlatformDataExceptPod := n.metaData.GetPlatformDataOP().GetAllCompletePlatformDataExceptPod()
		if localRegion == "" {
			n.updatePlatformData(allCompletePlatformDataExceptPod)
		} else {
			regionToPlatformDataOnlyPod := n.metaData.GetPlatformDataOP().GetRegionToPlatformDataOnlyPod()
			if regionPlatformData, ok := regionToPlatformDataOnlyPod[localRegion]; ok {
				platformData := metadata.NewPlatformData("platformData", "", 0, PLATFORM_DATA_FOR_INGESTER_1)
				platformData.Merge(allCompletePlatformDataExceptPod)
				platformData.MergeInterfaces(regionPlatformData)
				platformData.GeneratePlatformDataResult()
				n.updatePlatformData(platformData)
			} else {
				n.updatePlatformData(allCompletePlatformDataExceptPod)
			}

		}
	case K8S_CLUSTER_IN_LOCAL_AZS:
		allCompletePlatformDataExceptPod := n.metaData.GetPlatformDataOP().GetAllCompletePlatformDataExceptPod()
		if len(localAZs) == 0 {
			n.updatePlatformData(allCompletePlatformDataExceptPod)
		} else {
			if Contains(localAZs, CONN_DEFAULT_AZ) {
				regionToPlatformDataOnlyPod := n.metaData.GetPlatformDataOP().GetRegionToPlatformDataOnlyPod()
				if regionPlatformData, ok := regionToPlatformDataOnlyPod[localRegion]; ok {
					platformData := metadata.NewPlatformData("platformData", "", 0, PLATFORM_DATA_FOR_INGESTER_2)
					platformData.Merge(allCompletePlatformDataExceptPod)
					platformData.MergeInterfaces(regionPlatformData)
					platformData.GeneratePlatformDataResult()
					n.updatePlatformData(platformData)
				} else {
					n.updatePlatformData(allCompletePlatformDataExceptPod)
				}
			} else {
				platformData := metadata.NewPlatformData("platformData", "", 0, PLATFORM_DATA_FOR_INGESTER_2)
				azToPlatformDataOnlyPod := n.metaData.GetPlatformDataOP().GetAZToPlatformDataOnlyPod()
				for _, az := range localAZs {
					if azPlatformData, ok := azToPlatformDataOnlyPod[az]; ok {
						platformData.MergeInterfaces(azPlatformData)
					}
				}
				platformData.Merge(allCompletePlatformDataExceptPod)
				platformData.GeneratePlatformDataResult()
				n.updatePlatformData(platformData)
			}
		}
	default:
		n.updatePlatformData(n.metaData.GetPlatformDataOP().GetAllPlatformDataForIngester())
	}
}

func (n *NodeInfo) registerTSDB() {
	log.Info(n.Log("start register rsdb"))
	data := n.tsdbRegister.getRegisterData()
	for _, tsdb := range data {
		n.registerTSDBToDB(tsdb)
	}
	log.Info(n.Log("end register tsdb"))
}

func (n *NodeInfo) PutChNodeInfo() {
	select {
	case n.chNodeInfo <- struct{}{}:
	default:
	}
}

func (n *NodeInfo) TimedRefreshNodeCache() {
	n.initTSDBInfo()
	n.generateControllerInfo()
	n.generatePlatformData()
	if n.GetORGID() == DEFAULT_ORG_ID {
		n.isRegisterController()
	}
	interval := time.Duration(n.config.NodeRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info(n.Log("start generate node cache data from timed"))
			if n.GetORGID() == DEFAULT_ORG_ID {
				n.isRegisterController()
				n.generateDataForDefaultORG()
			} else {
				n.generateDataForNotDefaultORG()
			}
			n.generatePlatformData()
			log.Info(n.Log("end generate node cache data from timed"))
		case <-n.chNodeInfo:
			log.Info(n.Log("start generate node cache data from rpc"))
			if n.GetORGID() == DEFAULT_ORG_ID {
				n.generateDataForDefaultORG()
			} else {
				n.generateDataForNotDefaultORG()
			}
			n.generatePlatformData()
			pushmanager.Broadcast()
			log.Info(n.Log("end generate node cache data from rpc"))
		case <-n.chRegister:
			n.registerTSDB()
		case <-n.ctx.Done():
			log.Info(n.Log("exit generate node data"))
			return
		}
	}
}
