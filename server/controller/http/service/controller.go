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

func GetControllers(orgID int, filter map[string]string) (resp []model.Controller, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var response []model.Controller
	var controllers []mysql.Controller
	var regions []mysql.Region
	var azs []mysql.AZ
	var azControllerconns []mysql.AZControllerConnection
	var vtaps []mysql.VTap

	analyzerName, analyzerNameOK := filter["analyzer_name"]
	analyzerIP, analyzerIpOK := filter["analyzer_ip"]
	if lcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", lcuuid)
	} else if ip, ok := filter["ip"]; ok {
		db = db.Where("ip = ?", ip)
	} else if name, ok := filter["name"]; ok && name != "" {
		db = db.Where("name = ? OR ip = ?", name, name)
	} else if analyzerNameOK || analyzerIpOK {
		analyzer := mysql.Analyzer{}
		if analyzerNameOK {
			db.Where("name = ?", analyzerName).First(&analyzer)
			if ret := db.Where("name = ?", analyzerName).First(&analyzer); ret.Error != nil {
				return []model.Controller{}, nil
			}
		} else {
			db.Where("ip = ?", analyzerIP).First(&analyzer)
			if ret := db.Where("ip = ?", analyzerIP).First(&analyzer); ret.Error != nil {
				return []model.Controller{}, nil
			}
		}
		azAnalyzerConns := []mysql.AZAnalyzerConnection{}
		db.Where("analyzer_ip = ?", analyzer.IP).Find(&azAnalyzerConns)
		region := ""
		if len(azAnalyzerConns) > 0 {
			region = azAnalyzerConns[0].Region
		}
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	} else if vtapName, ok := filter["vtap_name"]; ok {
		vtap := mysql.VTap{}
		if ret := db.Where("name = ?", vtapName).First(&vtap); ret.Error != nil {
			return []model.Controller{}, nil
		}
		az := mysql.AZ{}
		if ret := db.Where("lcuuid = ?", vtap.AZ).First(&az); ret.Error != nil {
			return []model.Controller{}, nil
		}
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		db.Where("region = ?", az.Region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	} else if region, ok := filter["region"]; ok {
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	}
	db.Find(&controllers)
	db.Find(&regions)
	db.Find(&azs)
	db.Find(&azControllerconns)
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

	ipToAzControllerCon := make(map[string][]*mysql.AZControllerConnection)
	for i, conn := range azControllerconns {
		ipToAzControllerCon[conn.ControllerIP] = append(
			ipToAzControllerCon[conn.ControllerIP],
			&azControllerconns[i],
		)
	}

	controllerIPToVtapCount := make(map[string]int)
	controllerIPToCurVtapCount := make(map[string]int)
	for _, vtap := range vtaps {
		controllerIPToVtapCount[vtap.ControllerIP]++
		controllerIPToCurVtapCount[vtap.CurControllerIP]++
	}

	for _, controller := range controllers {
		controllerResp := model.Controller{
			ID:                 controller.ID,
			IP:                 controller.IP,
			Name:               controller.Name,
			NodeType:           controller.NodeType,
			State:              controller.State,
			PodIP:              controller.PodIP,
			NatIP:              controller.NATIP,
			NatIPEnabled:       controller.NATIPEnabled,
			CPUNum:             controller.CPUNum,
			MemorySize:         controller.MemorySize,
			Arch:               controller.Arch,
			ArchType:           common.GetArchType(controller.Arch),
			Os:                 controller.Os,
			OsType:             common.GetOsType(controller.Os),
			KernelVersion:      controller.KernelVersion,
			VTapMax:            controller.VTapMax,
			RegionDomainPrefix: controller.RegionDomainPrefix,
			SyncedAt:           controller.SyncedAt,
			Lcuuid:             controller.Lcuuid,
		}

		// state
		if controller.State != common.HOST_STATE_COMPLETE && controller.State != common.HOST_STATE_MAINTENANCE {
			controllerResp.State = common.HOST_STATE_EXCEPTION
		} else {
			controllerResp.State = controller.State
		}
		// vtap_count
		if vtapCount, ok := controllerIPToVtapCount[controller.IP]; ok {
			controllerResp.VtapCount = vtapCount
		}
		// cur_vtap_count
		if vtapCount, ok := controllerIPToCurVtapCount[controller.IP]; ok {
			controllerResp.CurVtapCount = vtapCount
		}
		// region
		var azConns []*mysql.AZControllerConnection
		azConns, in := ipToAzControllerCon[controller.IP]
		if in {
			if region, ok := lcuuidToRegion[azConns[0].Region]; ok {
				controllerResp.Region = region.Lcuuid
				controllerResp.RegionName = region.Name
			}
		}
		// azs
		for _, azConn := range azConns {
			if azConn.AZ == "ALL" {
				controllerResp.IsAllAz = true
				if cAzs, ok := regionToAz[azConn.Region]; ok {
					for _, cAz := range cAzs {
						controllerResp.Azs = append(
							controllerResp.Azs, model.ControllerAz{
								Az:     cAz.Lcuuid,
								AzName: cAz.Name,
							},
						)
					}
				}
			} else {
				controllerResp.IsAllAz = false
				if cAz, ok := lcuuidToAz[azConn.AZ]; ok {
					controllerResp.Azs = append(
						controllerResp.Azs, model.ControllerAz{
							Az:     cAz.Lcuuid,
							AzName: cAz.Name,
						},
					)
				}
			}
		}

		response = append(response, controllerResp)
	}
	return response, nil
}

func UpdateController(
	orgID int, lcuuid string, controllerUpdate map[string]interface{},
	m *monitor.ControllerCheck, cfg *config.ControllerConfig,
) (resp *model.Controller, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var controller mysql.Controller
	var dbUpdateMap = make(map[string]interface{})

	if ret := db.Where("lcuuid = ?", lcuuid).First(&controller); ret.Error != nil {
		return nil, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("controller (%s) not found", lcuuid))
	}

	log.Infof("update controller (%s) config %v", controller.Name, controllerUpdate)

	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	// 修改最大关联采集器个数
	if _, ok := controllerUpdate["VTAP_MAX"]; ok {
		vtapMax := int(controllerUpdate["VTAP_MAX"].(float64))
		if err = tx.Model(controller).Update("vtap_max", vtapMax).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		// 如果小于当前的最大采集器个数，则触发部分采集器的控制器切换操作
		if vtapMax < controller.VTapMax {
			vtaps := []mysql.VTap{}
			updateVTapLcuuids := []string{}
			tx.Where("controller_ip = ?", controller.IP).Find(&vtaps)
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
				if err = tx.Model(&mysql.VTap{}).Where("lcuuid IN (?)", updateVTapLcuuids).Update("controller_ip", "").Error; err != nil {
					tx.Rollback()
					return nil, err
				}
				m.TriggerReallocController(dbInfo, "")
			}
		}
	}

	// 修改区域和可用区
	if _, ok := controllerUpdate["AZS"]; ok {
		azs := controllerUpdate["AZS"].([]interface{})
		if len(azs) > cfg.Spec.AZMaxPerServer {
			return nil, NewError(
				httpcommon.INVALID_POST_DATA,
				fmt.Sprintf(
					"max az num associated controller is (%d)", cfg.Spec.AZMaxPerServer,
				),
			)
		}

		// 判断哪些可用区存在控制器减少，触发对应的采集器重新分配控制器
		var (
			oldConnAzs, newConnAzs = mapset.NewSet(), mapset.NewSet()
			oldVTapAzs, newVTapAzs = mapset.NewSet(), mapset.NewSet()
			delConnAzs, addConnAzs = mapset.NewSet(), mapset.NewSet()
			delVTapAzs             = mapset.NewSet()
		)
		var controllerRegion string
		var azControllerConns []mysql.AZControllerConnection
		tx.Where("controller_ip = ?", controller.IP).Find(&azControllerConns)
		if len(azControllerConns) > 0 {
			controllerRegion = azControllerConns[0].Region
		} else {
			controllerRegion = common.DEFAULT_REGION
		}
		oldControllerRegion := controllerRegion
		for _, conn := range azControllerConns {
			oldConnAzs.Add(conn.AZ)
		}
		var dbAzs []mysql.AZ
		tx.Where("region = ?", controllerRegion).Find(&dbAzs)

		// - 存在区域修改时
		//   - 删除 vtap 逻辑
		//     - 如果旧配置是全部可用区，delVTapAzs 为 az 表所有的可用区
		//     - 否则 delVTapAzs 为 az_controller_connection 表的对应的可用区
		//   - 删除 az_controller_connection 逻辑
		//     - 如果旧配置是全部可用区，delConnAzs = "ALL"
		//     - 否则 delConnAzs =  az_controller_connection 表的对应的可用区
		//   - 增加 az_controller_connection 逻辑
		//     - 如果新配置是全部可用区，addConnAzs = "ALL"
		//     - 否则 addConnAzs = 新传入的 az
		// - 不存在区域修改时
		//   - 设置四个变量：oldVTapAzs、newVTapAzs、oldConnAzs、newConnAzs
		//     - oldVTapAzs：
		//       - 如果旧配置是全部可用区，oldVTapAzs = 原有区域（az表）中所有 az
		//       - 否则 oldVTapAzs = az_controller_connection 表中的 az
		//     - newVTapAzs：
		//       - 如果新配置是全部可用区，newVTapAzs = 原有区域（az表）中所有 az
		//       - 否则 newVTapAzs = 新传入的 az
		//     - oldConnAzs：
		//       - oldConnAzs =  az_controller_connection 表的 az
		//     - newConnAzs
		//       - 如果新配置是全部可用区，newConnAzs = "ALL"
		//       - 否则 newConnAzs = 新传入的 az
		//   - 删除 vtap 逻辑
		//     - delVTapAzs = oldVTapAzs - newVTapAzs
		//   - 删除 az_controller_connection 逻辑
		//     - delConnAzs = oldConnAzs - newConnAzs
		//   - 增加 az_controller_connection 逻辑
		//     - addConnAzs = newConnAzs - oldConnAzs
		if _, ok := controllerUpdate["REGION"]; ok {
			if oldConnAzs.Contains("ALL") {
				delConnAzs.Add("ALL")
				for _, az := range dbAzs {
					delVTapAzs.Add(az.Lcuuid)
				}
			} else {
				delConnAzs = oldConnAzs.Clone()
				delVTapAzs = delVTapAzs.Clone()
			}

			if _, ok := controllerUpdate["IS_ALL_AZ"]; ok {
				addConnAzs.Add("ALL")
			} else {
				for _, az := range azs {
					addConnAzs.Add(az)
				}
			}

			controllerRegion = controllerUpdate["REGION"].(string)
		} else {
			if oldConnAzs.Contains("ALL") {
				for _, az := range dbAzs {
					oldVTapAzs.Add(az.Lcuuid)
				}
			} else {
				oldVTapAzs = oldConnAzs.Clone()
			}

			var dbAzs []mysql.AZ
			tx.Where("region = ?", controllerRegion).Find(&dbAzs)
			if _, ok := controllerUpdate["IS_ALL_AZ"]; ok {
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

		log.Infof("oldConnAzs: %v, newConnAzs: %v, oldVTapAzs: %v, newVTapAzs: %v", oldConnAzs, newConnAzs, oldVTapAzs, newVTapAzs)
		log.Infof("addConnAzs: %v, delConnAzs: %v, delVTapAzs: %v", addConnAzs, delConnAzs, delVTapAzs)

		if len(delConnAzs.ToSlice()) > 0 {
			var azCondition []string
			for _, az := range delConnAzs.ToSlice() {
				azCondition = append(azCondition, az.(string))
			}
			if err = tx.Delete(mysql.AZControllerConnection{},
				"region = ? AND controller_ip = ? AND az IN (?)", oldControllerRegion, controller.IP, azCondition).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		var addConns []mysql.AZControllerConnection
		if len(addConnAzs.ToSlice()) > 0 {
			for _, az := range addConnAzs.ToSlice() {
				aConn := mysql.AZControllerConnection{}
				aConn.Region = controllerRegion
				aConn.AZ = az.(string)
				aConn.ControllerIP = controller.IP
				aConn.Lcuuid = uuid.New().String()
				addConns = append(addConns, aConn)
			}
			if err = tx.Create(&addConns).Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		// 针对 delVTap 中的采集器, 更新控制器IP为空，触发重新分配控制器
		if len(delVTapAzs.ToSlice()) > 0 {
			if err = tx.Model(&mysql.VTap{}).Where("az IN (?)", delVTapAzs.ToSlice()).Where("controller_ip = ?",
				controller.IP).Update("controller_ip", "").Error; err != nil {
				tx.Rollback()
				return nil, err
			}
		}

		m.TriggerReallocController(dbInfo, "")

		// TODO: 触发给采集器下发信息的推送
	}

	// 修改nat_ip
	if _, ok := controllerUpdate["NAT_IP"]; ok {
		// TODO: 触发给采集器下发信息的推送
		dbUpdateMap["nat_ip"] = controllerUpdate["NAT_IP"]
	}

	// 修改状态
	var state int
	if _, ok := controllerUpdate["STATE"]; ok {
		dbUpdateMap["state"] = controllerUpdate["STATE"]
		state = int(controllerUpdate["STATE"].(float64))
	}

	// 更新controller DB
	if err = tx.Model(&controller).Updates(dbUpdateMap).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// if state equal to maintaince/exception, trigger realloc controller
	// 如果是将状态修改为运维/异常，则触发对应的采集器重新分配控制器
	if state == common.HOST_STATE_MAINTENANCE || state == common.HOST_STATE_EXCEPTION {
		m.TriggerReallocController(dbInfo, controller.IP)
	}

	if err = tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	response, _ := GetControllers(orgID, map[string]string{"lcuuid": lcuuid})
	return &response[0], nil
}

func DeleteController(orgID int, lcuuid string, m *monitor.ControllerCheck) (resp map[string]string, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var controller mysql.Controller
	var vtapCount int64

	if ret := db.Where("lcuuid = ?", lcuuid).First(&controller); ret.Error != nil {
		return map[string]string{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("controller (%s) not found", lcuuid))
	}

	log.Infof("delete controller (%s)", controller.Name)

	db.Where("controller_ip = ?", controller.IP).Count(&vtapCount)
	if vtapCount > 0 {
		return map[string]string{}, NewError(httpcommon.INVALID_POST_DATA, fmt.Sprintf("controller (%s) is being used by vtap", lcuuid))
	}

	db.Delete(mysql.AZControllerConnection{}, "controller_ip = ?", controller.IP)
	db.Delete(&controller)

	// 触发对应的采集器重新分配控制器
	m.TriggerReallocController(dbInfo, controller.IP)

	return map[string]string{"LCUUID": lcuuid}, nil
}
