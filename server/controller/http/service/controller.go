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

func GetControllers(filter map[string]string) (resp []model.Controller, err error) {
	var response []model.Controller
	var controllers []mysql.Controller
	var regions []mysql.Region
	var azs []mysql.AZ
	var azControllerconns []mysql.AZControllerConnection
	var vtaps []mysql.VTap

	db := mysql.Db
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
			mysql.Db.Where("name = ?", analyzerName).First(&analyzer)
			if ret := mysql.Db.Where("name = ?", analyzerName).First(&analyzer); ret.Error != nil {
				return []model.Controller{}, nil
			}
		} else {
			mysql.Db.Where("ip = ?", analyzerIP).First(&analyzer)
			if ret := mysql.Db.Where("ip = ?", analyzerIP).First(&analyzer); ret.Error != nil {
				return []model.Controller{}, nil
			}
		}
		azAnalyzerConns := []mysql.AZAnalyzerConnection{}
		mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Find(&azAnalyzerConns)
		region := ""
		if len(azAnalyzerConns) > 0 {
			region = azAnalyzerConns[0].Region
		}
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		mysql.Db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	} else if vtapName, ok := filter["vtap_name"]; ok {
		vtap := mysql.VTap{}
		if ret := mysql.Db.Where("name = ?", vtapName).First(&vtap); ret.Error != nil {
			return []model.Controller{}, nil
		}
		az := mysql.AZ{}
		if ret := mysql.Db.Where("lcuuid = ?", vtap.AZ).First(&az); ret.Error != nil {
			return []model.Controller{}, nil
		}
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		mysql.Db.Where("region = ?", az.Region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	} else if region, ok := filter["region"]; ok {
		azConns := []mysql.AZControllerConnection{}
		ips := []string{}
		mysql.Db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.ControllerIP)
		}
		db = db.Where("ip IN (?)", ips)
	}
	db.Find(&controllers)
	mysql.Db.Find(&regions)
	mysql.Db.Find(&azs)
	mysql.Db.Find(&azControllerconns)
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
	lcuuid string, controllerUpdate map[string]interface{}, m *monitor.ControllerCheck,
	cfg *config.ControllerConfig,
) (resp model.Controller, err error) {
	var controller mysql.Controller
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&controller); ret.Error != nil {
		return model.Controller{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("controller (%s) not found", lcuuid))
	}

	log.Infof("update controller (%s) config %v", controller.Name, controllerUpdate)

	// 修改最大关联采集器个数
	if _, ok := controllerUpdate["VTAP_MAX"]; ok {
		vtapMax := int(controllerUpdate["VTAP_MAX"].(float64))
		mysql.Db.Model(controller).Update("vtap_max", vtapMax)

		// 如果小于当前的最大采集器个数，则触发部分采集器的控制器切换操作
		if vtapMax < controller.VTapMax {
			vtaps := []mysql.VTap{}
			updateVTapLcuuids := []string{}
			mysql.Db.Where("controller_ip = ?", controller.IP).Find(&vtaps)
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
				vtapDb := mysql.Db.Model(&mysql.VTap{})
				vtapDb = vtapDb.Where("lcuuid IN (?)", updateVTapLcuuids)
				vtapDb.Update("controller_ip", "")
				m.TriggerReallocController("")
			}
		}
	}

	// 修改区域和可用区
	if _, ok := controllerUpdate["AZS"]; ok {
		azs := controllerUpdate["AZS"].([]interface{})
		if len(azs) > cfg.Spec.AZMaxPerServer {
			return model.Controller{}, NewError(
				common.INVALID_POST_DATA,
				fmt.Sprintf(
					"max az num associated controller is (%d)", cfg.Spec.AZMaxPerServer,
				),
			)
		}
		// 判断哪些可用区存在控制器减少，触发对应的采集器重新分配控制器
		var azControllerConns []mysql.AZControllerConnection
		var addConns []mysql.AZControllerConnection
		var dbAzs []mysql.AZ
		var controllerRegion string
		var oldAzs = mapset.NewSet()
		var newAzs = mapset.NewSet()
		var delAzs = mapset.NewSet()
		var addAzs = mapset.NewSet()

		mysql.Db.Where("controller_ip = ?", controller.IP).Find(&azControllerConns)
		if len(azControllerConns) > 0 {
			controllerRegion = azControllerConns[0].Region
		} else {
			controllerRegion = common.DEFAULT_REGION
		}

		for _, conn := range azControllerConns {
			oldAzs.Add(conn.AZ)
		}

		// 存在区域修改时
		// - delAzs逻辑
		//   - 如果原来是全部可用区，则delAzs=原来区域的全部可用区
		//   - 否则delAzs=原有的可用区
		// - addAzs逻辑
		//   - 如果是配置全部可用区，则addAzs=ALL
		//   - 否则addAzs=配置的可用区
		// 不存在区域修改时
		// - delAzs=oldAzs-newAzs
		// - addAzs=newAzs-oldAzs
		if _, regionUpdate := controllerUpdate["REGION"]; regionUpdate {
			if oldAzs.Contains("ALL") {
				mysql.Db.Where("region = ?", controllerRegion).Find(&dbAzs)
				for _, az := range dbAzs {
					delAzs.Add(az.Lcuuid)
				}
			} else {
				delAzs = oldAzs
			}

			if _, azUpdate := controllerUpdate["IS_ALL_AZ"]; azUpdate {
				if controllerUpdate["IS_ALL_AZ"].(bool) {
					addAzs.Add("ALL")
				}
			}
			if !addAzs.Contains("ALL") {
				for _, az := range azs {
					addAzs.Add(az)
				}
			}
			controllerRegion = controllerUpdate["REGION"].(string)
		} else {

			if _, azUpdate := controllerUpdate["IS_ALL_AZ"]; azUpdate {
				if controllerUpdate["IS_ALL_AZ"].(bool) {
					newAzs.Add("ALL")
				}
			}
			if !newAzs.Contains("ALL") {
				for _, az := range azs {
					newAzs.Add(az)
				}
			}
			delAzs = oldAzs.Difference(newAzs)
			addAzs = newAzs.Difference(oldAzs)
		}

		// 针对delAzs, 删除azControllerconn
		var azCondition []string
		if oldAzs.Contains("ALL") {
			azCondition = append(azCondition, "ALL")
		} else {
			for _, az := range delAzs.ToSlice() {
				azCondition = append(azCondition, az.(string))
			}
		}
		mysql.Db.Where("controller_ip = ? AND az IN (?)", controller.IP, azCondition).Delete(mysql.AZControllerConnection{})

		// 针对addAzs, 插入azControllerconn
		for _, az := range addAzs.ToSlice() {
			aConn := mysql.AZControllerConnection{}
			aConn.Region = controllerRegion
			aConn.AZ = az.(string)
			aConn.ControllerIP = controller.IP
			aConn.Lcuuid = uuid.New().String()
			addConns = append(addConns, aConn)
		}
		mysql.Db.Create(&addConns)

		// 针对delAzs中的采集器, 更新控制器IP为空，触发重新分配控制器
		vtapDb := mysql.Db.Model(&mysql.VTap{})
		vtapDb = vtapDb.Where("az IN (?)", delAzs.ToSlice())
		vtapDb = vtapDb.Where("controller_ip = ?", controller.IP)
		vtapDb.Update("controller_ip", "")
		m.TriggerReallocController("")

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
	mysql.Db.Model(&controller).Updates(dbUpdateMap)

	// if state equal to maintaince/exception, trigger realloc controller
	// 如果是将状态修改为运维/异常，则触发对应的采集器重新分配控制器
	if state == common.HOST_STATE_MAINTENANCE || state == common.HOST_STATE_EXCEPTION {
		m.TriggerReallocController(controller.IP)
	}

	response, _ := GetControllers(map[string]string{"lcuuid": lcuuid})
	return response[0], nil
}

func DeleteController(lcuuid string, m *monitor.ControllerCheck) (resp map[string]string, err error) {
	var controller mysql.Controller
	var vtapCount int64

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&controller); ret.Error != nil {
		return map[string]string{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("controller (%s) not found", lcuuid))
	}

	log.Infof("delete controller (%s)", controller.Name)

	mysql.Db.Where("controller_ip = ?", controller.IP).Count(&vtapCount)
	if vtapCount > 0 {
		return map[string]string{}, NewError(common.INVALID_POST_DATA, fmt.Sprintf("controller (%s) is being used by vtap", lcuuid))
	}

	mysql.Db.Delete(mysql.AZControllerConnection{}, "controller_ip = ?", controller.IP)
	mysql.Db.Delete(&controller)

	// 触发对应的采集器重新分配控制器
	m.TriggerReallocController(controller.IP)

	return map[string]string{"LCUUID": lcuuid}, nil
}
