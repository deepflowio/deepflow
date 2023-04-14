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

package service

import (
	"fmt"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/monitor"
)

func GetAnalyzers(filter map[string]interface{}) (resp []model.Analyzer, err error) {
	var response []model.Analyzer
	var analyzers []mysql.Analyzer
	var controllers []mysql.Controller
	var regions []mysql.Region
	var azs []mysql.AZ
	var azAnalyzerconns []mysql.AZAnalyzerConnection
	var vtaps []mysql.VTap

	db := mysql.Db
	if lcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", lcuuid)
	} else if ip, ok := filter["ip"]; ok {
		db = db.Where("ip = ?", ip)
	} else if name, ok := filter["name"]; ok && name != "" {
		db = db.Where("name = ? OR ip = ?", name, name)
	} else if region, ok := filter["region"]; ok {
		azConns := []mysql.AZAnalyzerConnection{}
		ips := []string{}
		mysql.Db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.AnalyzerIP)
		}
		db = db.Where("ip IN (?)", ips)
	}
	if states, ok := filter["states"]; ok {
		db = db.Where("state IN (?)", states)
	}
	db.Find(&analyzers)
	mysql.Db.Find(&controllers)
	mysql.Db.Find(&regions)
	mysql.Db.Find(&azs)
	mysql.Db.Find(&azAnalyzerconns)
	mysql.Db.Find(&vtaps)

	lcuuidToRegion := make(map[string]*mysql.Region)
	for i, region := range regions {
		lcuuidToRegion[region.Lcuuid] = &regions[i]
	}

	lcuuidToAz := make(map[string]*mysql.AZ)
	regionToAz := make(map[string][]*mysql.AZ)
	for i, az := range azs {
		lcuuidToAz[az.Lcuuid] = &azs[i]
		regionToAz[az.Region] = append(regionToAz[az.Region], &azs[i])
	}

	ipToAzAnalyzerCon := make(map[string][]*mysql.AZAnalyzerConnection)
	for i, conn := range azAnalyzerconns {
		ipToAzAnalyzerCon[conn.AnalyzerIP] = append(
			ipToAzAnalyzerCon[conn.AnalyzerIP],
			&azAnalyzerconns[i],
		)
	}

	analyzerIPToVtapCount := make(map[string]int)
	analyzerIPToCurVtapCount := make(map[string]int)
	for _, vtap := range vtaps {
		analyzerIPToVtapCount[vtap.AnalyzerIP]++
		analyzerIPToCurVtapCount[vtap.CurAnalyzerIP]++
	}

	for _, analyzer := range analyzers {
		analyzerResp := model.Analyzer{
			ID:                analyzer.ID,
			IP:                analyzer.IP,
			Name:              analyzer.Name,
			State:             analyzer.State,
			PodIP:             analyzer.PodIP,
			NatIP:             analyzer.NATIP,
			NatIPEnabled:      analyzer.NATIPEnabled,
			Agg:               analyzer.Agg,
			PcapDataMountPath: analyzer.PcapDataMountPath,
			CPUNum:            analyzer.CPUNum,
			MemorySize:        analyzer.MemorySize,
			Arch:              analyzer.Arch,
			ArchType:          common.GetArchType(analyzer.Arch),
			Os:                analyzer.Os,
			OsType:            common.GetOsType(analyzer.Os),
			KernelVersion:     analyzer.KernelVersion,
			VTapMax:           analyzer.VTapMax,
			SyncedAt:          analyzer.SyncedAt,
			Lcuuid:            analyzer.Lcuuid,
		}

		// state
		if analyzer.State != common.HOST_STATE_COMPLETE && analyzer.State != common.HOST_STATE_MAINTENANCE {
			analyzerResp.State = common.HOST_STATE_EXCEPTION
		} else {
			analyzerResp.State = analyzer.State
		}
		// vtap_count
		if vtapCount, ok := analyzerIPToVtapCount[analyzer.IP]; ok {
			analyzerResp.VtapCount = vtapCount
		}
		// cur_vtap_count
		if vtapCount, ok := analyzerIPToCurVtapCount[analyzer.IP]; ok {
			analyzerResp.CurVtapCount = vtapCount
		}
		// region
		var azConns []*mysql.AZAnalyzerConnection
		azConns, in := ipToAzAnalyzerCon[analyzer.IP]
		if in {
			if region, ok := lcuuidToRegion[azConns[0].Region]; ok {
				analyzerResp.Region = region.Lcuuid
				analyzerResp.RegionName = region.Name
			}
		}
		// azs
		for _, azConn := range azConns {
			if azConn.AZ == "ALL" {
				analyzerResp.IsAllAz = true
				if cAzs, ok := regionToAz[azConn.Region]; ok {
					for _, cAz := range cAzs {
						analyzerResp.Azs = append(
							analyzerResp.Azs, model.AnalyzerAz{
								Az:     cAz.Lcuuid,
								AzName: cAz.Name,
							},
						)
					}
				}
			} else {
				analyzerResp.IsAllAz = false
				if cAz, ok := lcuuidToAz[azConn.AZ]; ok {
					analyzerResp.Azs = append(
						analyzerResp.Azs, model.AnalyzerAz{
							Az:     cAz.Lcuuid,
							AzName: cAz.Name,
						},
					)
				}
			}
		}

		response = append(response, analyzerResp)
	}
	return response, nil
}

func UpdateAnalyzer(
	lcuuid string, analyzerUpdate map[string]interface{}, m *monitor.AnalyzerCheck,
	cfg *config.ControllerConfig,
) (resp *model.Analyzer, err error) {
	var analyzer mysql.Analyzer
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return nil, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("update analyzer (%s) config %v", analyzer.Name, analyzerUpdate)

	tx := mysql.Db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	// 修改最大关联采集器个数
	if _, ok := analyzerUpdate["VTAP_MAX"]; ok {
		vtapMax := int(analyzerUpdate["VTAP_MAX"].(float64))
		if err = tx.Model(analyzer).Update("vtap_max", vtapMax).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		// TODO: 如果小于当前的最大采集器个数，则触发部分采集器的数据节点切换操作
		if vtapMax < analyzer.VTapMax {
			vtaps := []mysql.VTap{}
			updateVTapLcuuids := []string{}
			mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Find(&vtaps)
			if len(vtaps) > vtapMax {
				if vtapMax == 0 {
					for _, vtap := range vtaps {
						updateVTapLcuuids = append(updateVTapLcuuids, vtap.Lcuuid)
					}
				} else {
					for i := vtapMax; i < len(vtaps); i++ {
						updateVTapLcuuids = append(updateVTapLcuuids, vtaps[i].Lcuuid)
					}
				}
				if err = tx.Model(&mysql.VTap{}).Where("lcuuid IN (?)", updateVTapLcuuids).Update("analyzer_ip", "").Error; err != nil {
					tx.Rollback()
					return nil, err
				}
				m.TriggerReallocAnalyzer("")
			}
		}
	}

	// 检查: 如果区域内没有控制器，禁止将数据节点修改至该区域
	if _, ok := analyzerUpdate["REGION"]; ok {
		var azAnalyzerConns []mysql.AZAnalyzerConnection
		mysql.Db.Where("region = ?", analyzerUpdate["REGION"]).Find(&azAnalyzerConns)
		if len(azAnalyzerConns) == 0 {
			return nil, NewError(common.INVALID_POST_DATA, fmt.Sprintf("no controller in region(%s)", analyzerUpdate["REGION"]))
		}
	}
	// 修改区域和可用区
	oldConn, newConn := mapset.NewSet(), mapset.NewSet()
	oldVTap, newVTap := mapset.NewSet(), mapset.NewSet()
	if _, ok := analyzerUpdate["AZS"]; ok {
		azs := analyzerUpdate["AZS"].([]interface{})
		if len(azs) > cfg.Spec.AZMaxPerServer {
			return nil, NewError(
				common.INVALID_POST_DATA,
				fmt.Sprintf(
					"max az num associated analyzer is (%d)", cfg.Spec.AZMaxPerServer,
				),
			)
		}
		// 判断哪些可用区存在控制器减少，触发对应的采集器重新分配数据节点
		var analyzerRegion string
		var azAnalyzerConns []mysql.AZAnalyzerConnection
		mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Find(&azAnalyzerConns)
		if len(azAnalyzerConns) > 0 {
			analyzerRegion = azAnalyzerConns[0].Region
		} else {
			analyzerRegion = common.DEFAULT_REGION
		}
		for _, conn := range azAnalyzerConns {
			oldConn.Add(conn.AZ)
		}
		var dbVTaps []mysql.VTap
		tx.Where("region = ? and analyzer_ip = ?", analyzerRegion, analyzer.IP).Find(&dbVTaps)
		for _, vtap := range dbVTaps {
			oldVTap.Add(vtap.AZ)
		}

		var dbAzs []mysql.AZ
		tx.Where("region = ?", analyzerRegion).Find(&dbAzs)
		if _, ok := analyzerUpdate["IS_ALL_AZ"]; ok {
			newConn.Add("ALL")
			for _, dbAz := range dbAzs {
				newVTap.Add(dbAz.Lcuuid)
			}
		} else {
			for _, az := range azs {
				newConn.Add(az)
				newVTap.Add(az)
			}
		}

		addConn := newConn.Difference(oldConn)
		delConn := oldConn.Difference(newConn)
		delVTap := oldVTap.Difference(newVTap)

		if _, ok := analyzerUpdate["REGION"]; ok {
			delConn, newConn = mapset.NewSet(), mapset.NewSet()
			if oldConn.Contains("ALL") {
				delConn.Add("ALL")
			} else {
				delConn = oldConn.Clone()
			}

			if _, ok := analyzerUpdate["IS_ALL_AZ"]; ok {
				addConn.Add("ALL")
			} else {
				for _, az := range azs {
					addConn.Add(az)
				}
			}

			delVTap = mapset.NewSet()
			for _, vtap := range dbVTaps {
				delVTap.Add(vtap.AZ)
			}
			analyzerRegion = analyzerUpdate["REGION"].(string)
		}

		log.Infof("oldConn: %v, newConn: %v, oldVTap: %v, newVTap: %v", oldConn, newConn, oldVTap, newVTap)
		log.Infof("addConn: %v, delConn: %v, delVTap: %v", addConn, delConn, delVTap)

		if len(delConn.ToSlice()) > 0 {
			var azCondition []string
			for _, az := range delConn.ToSlice() {
				azCondition = append(azCondition, az.(string))
			}
			if err = tx.Delete(mysql.AZAnalyzerConnection{},
				"analyzer_ip = ? AND az IN (?)", analyzer.IP, azCondition).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		var addConns []mysql.AZAnalyzerConnection
		if len(addConn.ToSlice()) > 0 {
			for _, az := range addConn.ToSlice() {
				aConn := mysql.AZAnalyzerConnection{}
				aConn.Region = analyzerRegion
				aConn.AZ = az.(string)
				aConn.AnalyzerIP = analyzer.IP
				aConn.Lcuuid = uuid.New().String()
				addConns = append(addConns, aConn)
			}
			if err = tx.Create(&addConns).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		// 针对 delVTap 中的采集器, 更新控制器IP为空，触发重新分配控制器
		if len(delVTap.ToSlice()) > 0 {
			if err = tx.Model(&mysql.VTap{}).Where("az IN (?)", delVTap.ToSlice()).Where("analyzer_ip = ?",
				analyzer.IP).Update("analyzer_ip", "").Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		m.TriggerReallocAnalyzer("")
	}

	// 修改nat_ip
	if _, ok := analyzerUpdate["NAT_IP"]; ok {
		// TODO: 触发给数据节点下发信息的推送
		dbUpdateMap["nat_ip"] = analyzerUpdate["NAT_IP"]
	}

	// 修改是否参与聚合
	if _, ok := analyzerUpdate["AGG"]; ok {
		dbUpdateMap["agg"] = analyzerUpdate["AGG"]
	}

	// 修改状态
	var state int
	if _, ok := analyzerUpdate["STATE"]; ok {
		dbUpdateMap["state"] = analyzerUpdate["STATE"]
		state = int(analyzerUpdate["STATE"].(float64))
	}

	// 更新analyzer DB
	if err = tx.Model(&analyzer).Updates(dbUpdateMap).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// if state equal to maintaince/exception, trigger realloc analyzer
	// 如果是将状态修改为运维/异常，则触发对应的采集器重新分配数据节点
	if state == common.HOST_STATE_MAINTENANCE || state == common.HOST_STATE_EXCEPTION {
		m.TriggerReallocAnalyzer(analyzer.IP)
	}

	if err = tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	response, _ := GetAnalyzers(map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func DeleteAnalyzer(lcuuid string, m *monitor.AnalyzerCheck) (resp map[string]string, err error) {
	var analyzer mysql.Analyzer
	var vtapCount int64

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return map[string]string{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("delete analyzer (%s)", analyzer.Name)

	mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Count(&vtapCount)
	if vtapCount > 0 {
		return map[string]string{}, NewError(common.INVALID_POST_DATA, fmt.Sprintf("analyzer (%s) is being used by vtap", lcuuid))
	}

	mysql.Db.Delete(mysql.AZAnalyzerConnection{}, "analyzer_ip = ?", analyzer.IP)
	mysql.Db.Delete(&analyzer)

	// 触发对应的采集器重新分配数据节点
	m.TriggerReallocAnalyzer(analyzer.IP)

	return map[string]string{"LCUUID": lcuuid}, nil
}
