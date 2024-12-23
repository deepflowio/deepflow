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

package monitor

import (
	"context"
	"sort"
	"time"

	mapset "github.com/deckarep/golang-set"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/rebalance"
	mconfig "github.com/deepflowio/deepflow/server/controller/monitor/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

type AnalyzerCheck struct {
	cCtx                  context.Context
	cCancel               context.CancelFunc
	cfg                   mconfig.MonitorConfig
	healthCheckPort       int
	healthCheckNodePort   int
	ch                    chan dbAndIP
	normalAnalyzerDict    map[string]*dfHostCheck
	exceptionAnalyzerDict map[string]*dfHostCheck
}

func NewAnalyzerCheck(cfg *config.ControllerConfig, ctx context.Context) *AnalyzerCheck {
	cCtx, cCancel := context.WithCancel(ctx)
	return &AnalyzerCheck{
		cCtx:                  cCtx,
		cCancel:               cCancel,
		cfg:                   cfg.MonitorCfg,
		healthCheckPort:       cfg.ListenPort,
		healthCheckNodePort:   cfg.ListenNodePort,
		ch:                    make(chan dbAndIP, cfg.MonitorCfg.HealthCheckHandleChannelLen),
		normalAnalyzerDict:    make(map[string]*dfHostCheck),
		exceptionAnalyzerDict: make(map[string]*dfHostCheck),
	}
}

func (c *AnalyzerCheck) Start(sCtx context.Context) {
	log.Info("analyzer check start")
	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.SyncDefaultORGDataInterval) * time.Second)
		defer ticker.Stop()
	LOOP1:
		for {
			select {
			case <-ticker.C:
				c.SyncDefaultOrgData()
			case <-sCtx.Done():
				break LOOP1
			case <-c.cCtx.Done():
				break LOOP1
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.HealthCheckInterval) * time.Second)
		defer ticker.Stop()
	LOOP2:
		for {
			select {
			case <-ticker.C:
				if err := metadb.GetDBs().DoOnAllDBs(func(db *metadb.DB) error {
					// 数据节点健康检查
					c.healthCheck(db)
					// 检查没有分配数据节点的采集器，并进行分配
					c.vtapAnalyzerCheck(db)
					// check az_analyzer_connection, delete unused item
					c.azConnectionCheck(db)
					return nil
				}); err != nil {
					log.Error(err)
				}
			case <-sCtx.Done():
				break LOOP2
			case <-c.cCtx.Done():
				break LOOP2
			}
		}
	}()

	cfg := c.cfg.IngesterLoadBalancingConfig
	// 根据ch信息，针对部分采集器分配/重新分配数据节点
	go func() {
		for {
			dbAndIP := <-c.ch

			if cfg.Algorithm == common.ANALYZER_ALLOC_BY_AGENT_COUNT {
				c.vtapAnalyzerAlloc(dbAndIP.db, dbAndIP.ip)
			} else if cfg.Algorithm == common.ANALYZER_ALLOC_BY_INGESTED_DATA {
				rebalance.NewAnalyzerInfo(false).RebalanceAnalyzerByTraffic(dbAndIP.db, false, cfg.DataDuration)
			} else {
				log.Errorf("algorithm(%s) is not supported, only supports: %s, %s", cfg.Algorithm,
					common.ANALYZER_ALLOC_BY_INGESTED_DATA, common.ANALYZER_ALLOC_BY_AGENT_COUNT)
				return
			}
			refresh.RefreshCache(dbAndIP.db.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
		}
	}()
}

func (c *AnalyzerCheck) Stop() {
	if c.cCancel != nil {
		c.cCancel()
	}
	log.Info("analyzer check stopped")
}

var checkExceptionAnalyzers = make(map[string]*dfHostCheck)

func (c *AnalyzerCheck) healthCheck(orgDB *metadb.DB) {
	var controllers []metadbmodel.Controller
	var analyzers []metadbmodel.Analyzer
	var exceptionIPs []string

	log.Info("analyzer health check start")

	if err := metadb.DefaultDB.Find(&controllers).Error; err != nil {
		log.Error(err)
	}
	ipToController := make(map[string]*metadbmodel.Controller)
	for i, controller := range controllers {
		ipToController[controller.IP] = &controllers[i]
	}

	if err := metadb.DefaultDB.Where("state != ?", common.HOST_STATE_MAINTENANCE).Order("state desc").Find(&analyzers).Error; err != nil {
		log.Errorf("get analyzer from db error: %v", err)
		return
	}
	for _, analyzer := range analyzers {
		// use pod ip in master region if pod_ip != null
		analyzerIP := analyzer.IP
		healthCheckPort := c.healthCheckNodePort
		if controller, ok := ipToController[analyzer.IP]; ok {
			if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER && len(controller.PodIP) != 0 {
				analyzerIP = controller.PodIP
				healthCheckPort = c.healthCheckPort
			}
		}

		// 检查逻辑同控制器
		active := isActive(common.HEALTH_CHECK_URL, analyzerIP, healthCheckPort)
		if analyzer.State == common.HOST_STATE_COMPLETE {
			if active {
				if _, ok := c.normalAnalyzerDict[analyzer.IP]; ok {
					delete(c.normalAnalyzerDict, analyzer.IP)
				}
				if _, ok := c.exceptionAnalyzerDict[analyzer.IP]; ok {
					delete(c.exceptionAnalyzerDict, analyzer.IP)
				}
				delete(checkExceptionAnalyzers, analyzer.IP)
			} else {
				if _, ok := c.exceptionAnalyzerDict[analyzer.IP]; ok {
					if c.exceptionAnalyzerDict[analyzer.IP].duration() >= int64(3*common.HEALTH_CHECK_INTERVAL.Seconds()) {
						delete(c.exceptionAnalyzerDict, analyzer.IP)
						if err := metadb.DefaultDB.Model(&analyzer).Update("state", common.HOST_STATE_EXCEPTION).Error; err != nil {
							log.Errorf("update analyzer(name: %s, ip: %s) state error: %v", analyzer.Name, analyzer.IP, err)
						}
						exceptionIPs = append(exceptionIPs, analyzer.IP)
						log.Infof("set analyzer (%s) state to exception", analyzer.IP)
						// 根据exceptionIP，重新分配对应采集器的数据节点
						c.TriggerReallocAnalyzer(orgDB, analyzer.IP)
						if _, ok := checkExceptionAnalyzers[analyzer.IP]; ok == false {
							checkExceptionAnalyzers[analyzer.IP] = newDFHostCheck()
						}
					}
				} else {
					c.exceptionAnalyzerDict[analyzer.IP] = newDFHostCheck()
				}
			}
		} else {
			if _, ok := checkExceptionAnalyzers[analyzer.IP]; ok == false {
				checkExceptionAnalyzers[analyzer.IP] = newDFHostCheck()
			}
			if active {
				if _, ok := c.normalAnalyzerDict[analyzer.IP]; ok {
					if c.normalAnalyzerDict[analyzer.IP].duration() >= int64(3*common.HEALTH_CHECK_INTERVAL.Seconds()) {
						delete(c.normalAnalyzerDict, analyzer.IP)
						if err := metadb.DefaultDB.Model(&analyzer).Update("state", common.HOST_STATE_COMPLETE).Error; err != nil {
							log.Errorf("update analyzer(name: %s, ip: %s) state error: %v", analyzer.Name, analyzer.IP, err)
						}
						log.Infof("set analyzer (%s) state to normal", analyzer.IP)
						delete(checkExceptionAnalyzers, analyzer.IP)
					}
				} else {
					c.normalAnalyzerDict[analyzer.IP] = newDFHostCheck()
				}
			} else {
				if _, ok := c.normalAnalyzerDict[analyzer.IP]; ok {
					delete(c.normalAnalyzerDict, analyzer.IP)
				}
				if _, ok := c.exceptionAnalyzerDict[analyzer.IP]; ok {
					delete(c.exceptionAnalyzerDict, analyzer.IP)
				}
			}
		}
	}
	for ip, dfhostCheck := range checkExceptionAnalyzers {
		if dfhostCheck.duration() > int64(c.cfg.ExceptionTimeFrame) {
			if err := orgDB.Delete(metadbmodel.AZAnalyzerConnection{}, "analyzer_ip = ?", ip).Error; err != nil {
				log.Errorf("delete az_analyzer_connection(ip: %s) error: %s", ip, err.Error(), orgDB.LogPrefixORGID)
			}
			err := metadb.DefaultDB.Delete(metadbmodel.Analyzer{}, "ip = ?", ip).Error
			if err != nil {
				log.Errorf("delete analyzer(%s) failed, err:%s", ip, err)
			} else {
				log.Infof("delete analyzer(%s), exception lasts for %d seconds", ip, dfhostCheck.duration())
				delete(checkExceptionAnalyzers, ip)
			}
		}
	}
	log.Info("analyzer health check end")
}

func (c *AnalyzerCheck) TriggerReallocAnalyzer(orgDB *metadb.DB, analyzerIP string) {
	c.ch <- dbAndIP{db: orgDB, ip: analyzerIP}
}

func (c *AnalyzerCheck) vtapAnalyzerCheck(orgDB *metadb.DB) {
	var vtaps []metadbmodel.VTap
	var noAnalyzerVtapCount int64

	log.Info("vtap analyzer check start", orgDB.LogPrefixORGID)

	ipMap, err := getIPMap(common.HOST_TYPE_ANALYZER)
	if err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
	}

	if err := orgDB.Where("type != ?", common.VTAP_TYPE_TUNNEL_DECAPSULATION).Find(&vtaps).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
		return
	}
	for _, vtap := range vtaps {
		// check vtap.analyzer_ip is not in controller.ip, set to empty if not exist
		if _, ok := ipMap[vtap.AnalyzerIP]; !ok {
			log.Infof("analyzer ip(%s) in vtap(%s) is invalid", vtap.AnalyzerIP, vtap.Name, orgDB.LogPrefixORGID)
			vtap.AnalyzerIP = ""
			if err := orgDB.Model(&metadbmodel.VTap{}).Where("lcuuid = ?", vtap.Lcuuid).Update("analyzer_ip", "").Error; err != nil {
				log.Errorf("update vtap(lcuuid: %s, name: %s) analyzer ip to empty error: %v", vtap.Lcuuid, vtap.Name, err, orgDB.LogPrefixORGID)
			}
		}

		if vtap.AnalyzerIP == "" {
			noAnalyzerVtapCount += 1
		} else if vtap.Exceptions&common.VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED != 0 {
			// 检查是否存在已分配数据节点，但异常未清除的采集器
			exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED
			orgDB.Model(&vtap).Update("exceptions", exceptions)
		}
	}
	// 如果存在没有数据节点的采集器，触发数据节点重新分配
	if noAnalyzerVtapCount > 0 {
		c.TriggerReallocAnalyzer(orgDB, "")
	}
	log.Info("vtap analyzer check end", orgDB.LogPrefixORGID)
}

func (c *AnalyzerCheck) vtapAnalyzerAlloc(orgDB *metadb.DB, excludeIP string) {
	var vtaps []metadbmodel.VTap
	var analyzers []metadbmodel.Analyzer
	var azs []metadbmodel.AZ
	var azAnalyzerConns []metadbmodel.AZAnalyzerConnection

	log.Info("vtap analyzer alloc start", orgDB.LogPrefixORGID)

	if err := orgDB.Where("type != ?", common.VTAP_TYPE_TUNNEL_DECAPSULATION).Find(&vtaps).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
		return
	}
	if err := orgDB.Where("state = ?", common.HOST_STATE_COMPLETE).Find(&analyzers).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
		return
	}

	// 获取待分配采集器对应的可用区信息
	// 获取数据节点当前已分配的采集器个数
	azToNoAnalyzerVTaps := make(map[string][]*metadbmodel.VTap)
	analyzerIPToUsedVTapNum := make(map[string]int)
	azLcuuids := mapset.NewSet()
	for i, vtap := range vtaps {
		if vtap.AnalyzerIP != "" && vtap.AnalyzerIP != excludeIP {
			analyzerIPToUsedVTapNum[vtap.AnalyzerIP] += 1
			continue
		}
		azToNoAnalyzerVTaps[vtap.AZ] = append(azToNoAnalyzerVTaps[vtap.AZ], &vtaps[i])
		azLcuuids.Add(vtap.AZ)
	}
	// 获取数据节点的剩余采集器个数
	analyzerIPToAvailableVTapNum := make(map[string]int)
	for _, analyzer := range analyzers {
		analyzerIPToAvailableVTapNum[analyzer.IP] = analyzer.VTapMax
		if usedVTapNum, ok := analyzerIPToUsedVTapNum[analyzer.IP]; ok {
			analyzerIPToAvailableVTapNum[analyzer.IP] = analyzer.VTapMax - usedVTapNum
		}
	}

	// 根据可用区查询region信息
	if err := orgDB.Where("lcuuid IN (?)", azLcuuids.ToSlice()).Find(&azs).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
		return
	}
	regionToAZLcuuids := make(map[string][]string)
	regionLcuuids := mapset.NewSet()
	for _, az := range azs {
		regionToAZLcuuids[az.Region] = append(regionToAZLcuuids[az.Region], az.Lcuuid)
		regionLcuuids.Add(az.Region)
	}

	// 获取可用区中的数据节点IP
	orgDB.Where("region IN (?)", regionLcuuids.ToSlice()).Find(&azAnalyzerConns)
	azToAnalyzerIPs := make(map[string][]string)
	for _, conn := range azAnalyzerConns {
		if conn.AZ == "ALL" {
			if azLcuuids, ok := regionToAZLcuuids[conn.Region]; ok {
				for _, azLcuuid := range azLcuuids {
					azToAnalyzerIPs[azLcuuid] = append(azToAnalyzerIPs[azLcuuid], conn.AnalyzerIP)
				}
			}
		} else {
			azToAnalyzerIPs[conn.AZ] = append(azToAnalyzerIPs[conn.AZ], conn.AnalyzerIP)
		}
	}

	// 遍历待分配采集器，分配数据节点IP
	for az, noAnalyzerVtaps := range azToNoAnalyzerVTaps {
		// 获取可分配的数据节点列表
		analyzerAvailableVTapNum := []common.KVPair{}
		if analyzerIPs, ok := azToAnalyzerIPs[az]; ok {
			for _, analyzerIP := range analyzerIPs {
				if availableVTapNum, ok := analyzerIPToAvailableVTapNum[analyzerIP]; ok {
					analyzerAvailableVTapNum = append(
						analyzerAvailableVTapNum,
						common.KVPair{Key: analyzerIP, Value: availableVTapNum},
					)
				}
			}
		}

		for _, vtap := range noAnalyzerVtaps {
			// 分配数据节点失败，更新异常错误码
			if len(analyzerAvailableVTapNum) == 0 {
				log.Warningf("no available analyzer for vtap (%s)", vtap.Name, orgDB.LogPrefixORGID)
				exceptions := vtap.Exceptions | common.VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED
				if err := orgDB.Model(&vtap).Update("exceptions", exceptions).Error; err != nil {
					log.Errorf("update vtap(name: %s) exceptions(%d) error: %v", vtap.Name, exceptions, err, orgDB.LogPrefixORGID)
				}
				continue
			}
			sort.Slice(analyzerAvailableVTapNum, func(i, j int) bool {
				return analyzerAvailableVTapNum[i].Value > analyzerAvailableVTapNum[j].Value
			})
			// Search for controllers that have capacity. If none has capacity, the collector limit is allowed.
			// There are five types of Value in analyzerAvailableVTapNum:
			// 1. All positive numbers
			// 2. Positive numbers and 0
			// 3. All are 0
			// 4, 0 and negative numbers
			// 5. All negative numbers
			analyzerAvailableVTapNum[0].Value -= 1
			analyzerIPToAvailableVTapNum[analyzerAvailableVTapNum[0].Key] -= 1

			// 分配数据节点成功，更新数据节点IP + 清空数据节点分配失败的错误码
			log.Infof("alloc analyzer (%s) for vtap (%s)", analyzerAvailableVTapNum[0].Key, vtap.Name, orgDB.LogPrefixORGID)
			if err := orgDB.Model(&vtap).Update("analyzer_ip", analyzerAvailableVTapNum[0].Key).Error; err != nil {
				log.Error(err, orgDB.LogPrefixORGID)
			}
			if vtap.Exceptions&common.VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED != 0 {
				exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED
				orgDB.Model(&vtap).Update("exceptions", exceptions)
			}
		}
	}
	log.Info("vtap analyzer alloc end")
}

func (c *AnalyzerCheck) azConnectionCheck(orgDB *metadb.DB) {
	var azs []metadbmodel.AZ
	var azAnalyzerConns []metadbmodel.AZAnalyzerConnection
	var analyzers []metadbmodel.Analyzer
	var regions []metadbmodel.Region

	log.Info("az connection check start", orgDB.LogPrefixORGID)

	if err := orgDB.Find(&azs).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
		return
	}
	azLcuuidToName := make(map[string]string)
	for _, az := range azs {
		azLcuuidToName[az.Lcuuid] = az.Name
	}

	analyzerIPToConn := make(map[string]metadbmodel.AZAnalyzerConnection)
	if err := orgDB.Find(&azAnalyzerConns).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
	}
	for _, conn := range azAnalyzerConns {
		analyzerIPToConn[conn.AnalyzerIP] = conn
		if conn.AZ == "ALL" {
			continue
		}
		if name, ok := azLcuuidToName[conn.AZ]; !ok {
			if err := orgDB.Delete(&conn).Error; err != nil {
				log.Infof("delete analyzer (ip: %s) az (name: %s, lcuuid: %s, region: %s) connection",
					conn.AnalyzerIP, name, conn.AZ, conn.Region, orgDB.LogPrefixORGID)
			}
			log.Infof("delete analyzer (%s) az (%s) connection", conn.AnalyzerIP, name, orgDB.LogPrefixORGID)
		}
	}

	if err := orgDB.Find(&regions).Error; err != nil {
		log.Error(err, orgDB.LogPrefixORGID)
	}
	if len(regions) == 1 {
		var deleteAnalyzers []metadbmodel.Analyzer
		if err := orgDB.Find(&analyzers).Error; err != nil {
			log.Error(err, orgDB.LogPrefixORGID)
		}
		for _, analyzer := range analyzers {
			if _, ok := analyzerIPToConn[analyzer.IP]; ok == false {
				deleteAnalyzers = append(deleteAnalyzers, analyzer)
			}
		}
		for _, deleteAnalyzer := range deleteAnalyzers {
			if err := orgDB.Delete(&deleteAnalyzer).Error; err != nil {
				log.Infof("delete analyzer (ip: %s, name: %s) error: %s", deleteAnalyzer.IP, deleteAnalyzer.Name, err, orgDB.LogPrefixORGID)
			}
			log.Infof("delete analyzer (%s) because no az_analyzer_conn", deleteAnalyzer.IP, orgDB.LogPrefixORGID)
		}
	}

	log.Info("az connection check end", orgDB.LogPrefixORGID)
}

var SyncAnalyzerExcludeField = []string{"nat_ip", "agg", "state"}

func (c *AnalyzerCheck) SyncDefaultOrgData() {
	var analyzers []metadbmodel.Analyzer
	if err := metadb.DefaultDB.Find(&analyzers).Error; err != nil {
		log.Error(err)
	}
	if err := metadb.SyncDefaultOrgData(analyzers, SyncAnalyzerExcludeField); err != nil {
		log.Error(err)
	}
}
