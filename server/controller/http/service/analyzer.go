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

package service

import (
	"fmt"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/monitor"
)

func GetAnalyzers(orgID int, filter map[string]interface{}) (resp []model.Analyzer, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var response []model.Analyzer
	var analyzers []mysql.Analyzer
	var controllers []mysql.Controller
	var regions []mysql.Region
	var azs []mysql.AZ
	var azAnalyzerconns []mysql.AZAnalyzerConnection
	var vtaps []mysql.VTap

	if lcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", lcuuid)
	} else if ip, ok := filter["ip"]; ok {
		db = db.Where("ip = ?", ip)
	} else if name, ok := filter["name"]; ok && name != "" {
		db = db.Where("name = ? OR ip = ?", name, name)
	} else if region, ok := filter["region"]; ok {
		azConns := []mysql.AZAnalyzerConnection{}
		ips := []string{}
		db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.AnalyzerIP)
		}
		db = db.Where("ip IN (?)", ips)
	}
	if states, ok := filter["states"]; ok {
		db = db.Where("state IN (?)", states)
	}
	db.Find(&analyzers)
	db.Find(&controllers)
	db.Find(&regions)
	db.Find(&azs)
	db.Find(&azAnalyzerconns)
	db.Find(&vtaps)

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
	orgID int, lcuuid string, analyzerUpdate map[string]interface{},
	m *monitor.AnalyzerCheck, cfg *config.ControllerConfig,
) (resp *model.Analyzer, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var analyzer mysql.Analyzer
	var dbUpdateMap = make(map[string]interface{})

	if ret := db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return nil, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("update analyzer (%s) config %v", analyzer.Name, analyzerUpdate)

	tx := db.Begin()
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
			db.Where("analyzer_ip = ?", analyzer.IP).Find(&vtaps)
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
		var azControllerConns []mysql.AZControllerConnection
		db.Where("region = ?", analyzerUpdate["REGION"]).Find(&azControllerConns)
		if len(azControllerConns) == 0 {
			return nil, NewError(httpcommon.INVALID_POST_DATA, fmt.Sprintf("no controller in region(%s)", analyzerUpdate["REGION"]))
		}
	}
	// 修改区域和可用区
	if _, ok := analyzerUpdate["AZS"]; ok {
		azs := analyzerUpdate["AZS"].([]interface{})
		if len(azs) > cfg.Spec.AZMaxPerServer {
			return nil, NewError(
				httpcommon.INVALID_POST_DATA,
				fmt.Sprintf(
					"max az num associated analyzer is (%d)", cfg.Spec.AZMaxPerServer,
				),
			)
		}
		// 判断哪些可用区存在控制器减少，触发对应的采集器重新分配数据节点
		var (
			oldConnAzs, newConnAzs = mapset.NewSet(), mapset.NewSet()
			oldVTapAzs, newVTapAzs = mapset.NewSet(), mapset.NewSet()
			delConnAzs, addConnAzs = mapset.NewSet(), mapset.NewSet()
			delVTapAzs             = mapset.NewSet()
		)
		var analyzerRegion string
		var azAnalyzerConns []mysql.AZAnalyzerConnection
		db.Where("analyzer_ip = ?", analyzer.IP).Find(&azAnalyzerConns)
		if len(azAnalyzerConns) > 0 {
			analyzerRegion = azAnalyzerConns[0].Region
		} else {
			analyzerRegion = common.DEFAULT_REGION
		}
		oldAnalyzerRegion := analyzerRegion
		for _, conn := range azAnalyzerConns {
			oldConnAzs.Add(conn.AZ)
		}
		var dbAzs []mysql.AZ
		tx.Where("region = ?", analyzerRegion).Find(&dbAzs)

		// - 存在区域修改时
		//   - 删除 vtap 逻辑
		//     - 如果旧配置是全部可用区，delVTapAzs 为 az 表所有的可用区
		//     - 否则 delVTapAzs 为 az_analyzer_connection 表的对应的可用区
		//   - 删除 az_analyzer_connection 逻辑
		//     - 如果旧配置是全部可用区，delConnAzs = "ALL"
		//     - 否则 delConnAzs =  az_analyzer_connection 表的对应的可用区
		//   - 增加 az_analyzer_connection 逻辑
		//     - 如果新配置是全部可用区，addConnAzs = "ALL"
		//     - 否则 addConnAzs = 新传入的 az
		// - 不存在区域修改时
		//   - 设置四个变量：oldVTapAzs、newVTapAzs、oldConnAzs、newConnAzs
		//     - oldVTapAzs：
		//       - 如果旧配置是全部可用区，oldVTapAzs = 原有区域（az表）中所有 az
		//       - 否则 oldVTapAzs = az_analyzer_connection 表中的 az
		//     - newVTapAzs：
		//       - 如果新配置是全部可用区，newVTapAzs = 原有区域（az表）中所有 az
		//       - 否则 newVTapAzs = 新传入的 az
		//     - oldConnAzs：
		//       - oldConnAzs =  az_analyzer_connection 表的 az
		//     - newConnAzs
		//       - 如果新配置是全部可用区，newConnAzs = "ALL"
		//       - 否则 newConnAzs = 新传入的 az
		//   - 删除 vtap 逻辑
		//     - delVTapAzs = oldVTapAzs - newVTapAzs
		//   - 删除 az_analyzer_connection 逻辑
		//     - delConnAzs = oldConnAzs - newConnAzs
		//   - 增加 az_analyzer_connection 逻辑
		//     - addConnAzs = newConnAzs - oldConnAzs
		if _, ok := analyzerUpdate["REGION"]; ok {
			if oldConnAzs.Contains("ALL") {
				delConnAzs.Add("ALL")
				for _, az := range dbAzs {
					delVTapAzs.Add(az.Lcuuid)
				}
			} else {
				delConnAzs = oldConnAzs.Clone()
				delVTapAzs = delVTapAzs.Clone()
			}

			if _, ok := analyzerUpdate["IS_ALL_AZ"]; ok {
				addConnAzs.Add("ALL")
			} else {
				for _, az := range azs {
					addConnAzs.Add(az)
				}
			}

			analyzerRegion = analyzerUpdate["REGION"].(string)
		} else {
			if oldConnAzs.Contains("ALL") {
				for _, az := range dbAzs {
					oldVTapAzs.Add(az.Lcuuid)
				}
			} else {
				oldVTapAzs = oldConnAzs.Clone()
			}

			var dbAzs []mysql.AZ
			tx.Where("region = ?", analyzerRegion).Find(&dbAzs)
			if _, ok := analyzerUpdate["IS_ALL_AZ"]; ok {
				newConnAzs.Add("ALL")
				for _, dbAz := range dbAzs {
					newVTapAzs.Add(dbAz.Lcuuid)
				}
			} else {
				for _, az := range azs {
					newConnAzs.Add(az)
					newVTapAzs.Add(az)
				}
			}

			addConnAzs = newConnAzs.Difference(oldConnAzs)
			delConnAzs = oldConnAzs.Difference(newConnAzs)
			delVTapAzs = oldVTapAzs.Difference(newVTapAzs)
		}

		if len(delConnAzs.ToSlice()) > 0 {
			var azCondition []string
			for _, az := range delConnAzs.ToSlice() {
				azCondition = append(azCondition, az.(string))
			}
			if err = tx.Delete(mysql.AZAnalyzerConnection{},
				"region = ? AND analyzer_ip = ? AND az IN (?)", oldAnalyzerRegion, analyzer.IP, azCondition).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		var addConnAzss []mysql.AZAnalyzerConnection
		if len(addConnAzs.ToSlice()) > 0 {
			for _, az := range addConnAzs.ToSlice() {
				aConn := mysql.AZAnalyzerConnection{}
				aConn.Region = analyzerRegion
				aConn.AZ = az.(string)
				aConn.AnalyzerIP = analyzer.IP
				aConn.Lcuuid = uuid.New().String()
				addConnAzss = append(addConnAzss, aConn)
			}
			if err = tx.Create(&addConnAzss).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		// 针对 delVTapAzs 中的采集器, 更新控制器IP为空，触发重新分配控制器
		if len(delVTapAzs.ToSlice()) > 0 {
			if err = tx.Model(&mysql.VTap{}).Where("az IN (?)", delVTapAzs.ToSlice()).Where("analyzer_ip = ?",
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
	response, _ := GetAnalyzers(orgID, map[string]interface{}{"lcuuid": lcuuid})
	return &response[0], nil
}

func DeleteAnalyzer(orgID int, lcuuid string, m *monitor.AnalyzerCheck) (resp map[string]string, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var analyzer mysql.Analyzer
	var vtapCount int64

	if ret := db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return map[string]string{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("delete analyzer (%s)", analyzer.Name)

	db.Where("analyzer_ip = ?", analyzer.IP).Count(&vtapCount)
	if vtapCount > 0 {
		return map[string]string{}, NewError(httpcommon.INVALID_POST_DATA, fmt.Sprintf("analyzer (%s) is being used by vtap", lcuuid))
	}

	db.Delete(mysql.AZAnalyzerConnection{}, "analyzer_ip = ?", analyzer.IP)
	db.Delete(&analyzer)

	// 触发对应的采集器重新分配数据节点
	m.TriggerReallocAnalyzer(analyzer.IP)

	return map[string]string{"LCUUID": lcuuid}, nil
}
