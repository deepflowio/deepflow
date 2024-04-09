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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
	mconfig "github.com/deepflowio/deepflow/server/controller/monitor/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

type dbAndIP struct {
	db *mysql.DB
	ip string
}

type ControllerCheck struct {
	cCtx                    context.Context
	cCancel                 context.CancelFunc
	cfg                     mconfig.MonitorConfig
	healthCheckPort         int
	healthCheckNodePort     int
	ch                      chan dbAndIP
	normalControllerDict    map[string]*dfHostCheck
	exceptionControllerDict map[string]*dfHostCheck
}

func NewControllerCheck(cfg *config.ControllerConfig, ctx context.Context) *ControllerCheck {
	cCtx, cCancel := context.WithCancel(ctx)
	return &ControllerCheck{
		cCtx:                    cCtx,
		cCancel:                 cCancel,
		cfg:                     cfg.MonitorCfg,
		healthCheckPort:         cfg.ListenPort,
		healthCheckNodePort:     cfg.ListenNodePort,
		ch:                      make(chan dbAndIP, cfg.MonitorCfg.HealthCheckHandleChannelLen),
		normalControllerDict:    make(map[string]*dfHostCheck),
		exceptionControllerDict: make(map[string]*dfHostCheck),
	}
}

func (c *ControllerCheck) Start() {
	log.Info("controller check start")
	go func() {
		for range time.Tick(time.Duration(c.cfg.SyncDefaultORGDataInterval) * time.Second) {
			c.SyncDefaultOrgData()
		}
	}()

	go func() {
		for range time.Tick(time.Duration(c.cfg.SyncDefaultORGDataInterval) * time.Second) {
			c.SyncDefaultOrgData()
		}
	}()

	go func() {
		for range time.Tick(time.Duration(c.cfg.HealthCheckInterval) * time.Second) {
			if err := mysql.GetDBs().DoOnAllDBs(func(db *mysql.DB) error {
				// 控制器健康检查
				c.healthCheck(db)
				// 检查没有分配控制器的采集器，并进行分配
				c.vtapControllerCheck(db)
				// check az_controller_connection, delete unused item
				c.azConnectionCheck(db)
				return nil
			}); err != nil {
				log.Error(err)
			}
		}
	}()

	// 根据ch信息，针对部分采集器分配/重新分配控制器
	go func() {
		for {
			dbAndIP := <-c.ch
			c.vtapControllerAlloc(dbAndIP.db, dbAndIP.ip)
			refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
		}
	}()

}

func (c *ControllerCheck) Stop() {
	if c.cCancel != nil {
		c.cCancel()
	}
	log.Info("controller check stopped")
}

var checkExceptionControllers = make(map[string]*dfHostCheck)

func (c *ControllerCheck) healthCheck(orgDB *mysql.DB) {
	var controllers []mysql.Controller
	var exceptionIPs []string

	log.Info("controller health check start")

	if err := mysql.DefaultDB.Where("state != ?", common.HOST_STATE_MAINTENANCE).Order("state desc").Find(&controllers).Error; err != nil {
		log.Errorf("get controller from db error: %v", err)
		return
	}
	for _, controller := range controllers {
		// 健康检查过程，为了防止网络抖动，(3 * interval)时间内都正常/异常才进行状态修改
		// 如果数据库状态是正常，且检查正常
		// - 检查是否在正常/异常Dict中
		//   - 如果在，则从异常Dict中移除
		//   - 如果不在，do nothing
		// 如果数据库状态是正常，但检测异常
		// - 检查是否在异常Dict中
		//   - 如果在，则检查是否已经满足一定时间内都是异常
		//     - 如果满足，则从异常Dict移除，且更新数据库状态为异常
		//     - 如果不满足，do nothing
		//   - 如果不在，则加入异常Dict
		// 如果数据库状态是异常，但检测正常
		// - 检查是否在正常Dict中
		//   - 如果在，则检查是否已经满足一定时间内都不是异常
		//     - 如果满足，则从正常Dict移除，且更新数据库状态为正常
		//     - 如果不满足，do nothing
		//   - 如果不在，则加入正常Dict
		// 如果数据库状态是异常，且检测异常
		// - 检查是否在正常/异常Dict中
		//   - 如果在，则从正常/异常Dict中移除
		//   - 如果不在，do nothing

		// use pod ip in master region if pod_ip != null
		controllerIP := controller.IP
		healthCheckPort := c.healthCheckNodePort
		if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER && len(controller.PodIP) != 0 {
			controllerIP = controller.PodIP
			healthCheckPort = c.healthCheckPort
		}
		active := isActive(common.HEALTH_CHECK_URL, controllerIP, healthCheckPort)
		if controller.State == common.HOST_STATE_COMPLETE {
			if active {
				if _, ok := c.normalControllerDict[controller.IP]; ok {
					delete(c.normalControllerDict, controller.IP)
				}
				if _, ok := c.exceptionControllerDict[controller.IP]; ok {
					delete(c.exceptionControllerDict, controller.IP)
				}
				delete(checkExceptionControllers, controller.IP)
			} else {
				if _, ok := c.exceptionControllerDict[controller.IP]; ok {
					if c.exceptionControllerDict[controller.IP].duration() >= int64(3*common.HEALTH_CHECK_INTERVAL.Seconds()) {
						delete(c.exceptionControllerDict, controller.IP)
						mysql.DefaultDB.Model(&controller).Update("state", common.HOST_STATE_EXCEPTION)
						exceptionIPs = append(exceptionIPs, controller.IP)
						log.Infof("set controller (%s) state to exception", controller.IP)
						// 根据exceptionIP，重新分配对应采集器的控制器
						c.TriggerReallocController(orgDB, controller.IP)
						if _, ok := checkExceptionControllers[controller.IP]; ok == false {
							checkExceptionControllers[controller.IP] = newDFHostCheck()
						}
					}
				} else {
					c.exceptionControllerDict[controller.IP] = newDFHostCheck()
				}
			}
		} else {
			if _, ok := checkExceptionControllers[controller.IP]; ok == false {
				checkExceptionControllers[controller.IP] = newDFHostCheck()
			}
			if active {
				if _, ok := c.normalControllerDict[controller.IP]; ok {
					if c.normalControllerDict[controller.IP].duration() >= int64(3*common.HEALTH_CHECK_INTERVAL.Seconds()) {
						delete(c.normalControllerDict, controller.IP)
						mysql.DefaultDB.Model(&controller).Update("state", common.HOST_STATE_COMPLETE)
						log.Infof("set controller (%s) state to normal", controller.IP)
						delete(checkExceptionControllers, controller.IP)
					}
				} else {
					c.normalControllerDict[controller.IP] = newDFHostCheck()
				}
			} else {
				if _, ok := c.normalControllerDict[controller.IP]; ok {
					delete(c.normalControllerDict, controller.IP)
				}
				if _, ok := c.exceptionControllerDict[controller.IP]; ok {
					delete(c.exceptionControllerDict, controller.IP)
				}
			}
		}
	}

	controllerIPs := []string{}
	for ip, dfhostCheck := range checkExceptionControllers {
		if dfhostCheck.duration() > int64(c.cfg.ExceptionTimeFrame) {
			orgDB.Delete(mysql.AZControllerConnection{}, "controller_ip = ?", ip)
			err := mysql.DefaultDB.Delete(mysql.Controller{}, "ip = ?", ip).Error
			if err != nil {
				log.Errorf("delete controller(%s) failed, err:%s", ip, err)
			} else {
				log.Infof("delete controller(%s), exception lasts for %d seconds", ip, dfhostCheck.duration())
				delete(checkExceptionControllers, ip)
			}
			controllerIPs = append(controllerIPs, ip)
		}
	}
	c.cleanExceptionControllerData(orgDB, controllerIPs)
	log.Info("controller health check end")
}

func (c *ControllerCheck) TriggerReallocController(orgDB *mysql.DB, controllerIP string) {
	c.ch <- dbAndIP{db: orgDB, ip: controllerIP}
}

func (c *ControllerCheck) vtapControllerCheck(orgDB *mysql.DB) {
	var vtaps []mysql.VTap
	var noControllerVtapCount int64

	log.Info("vtap controller check start")

	ipMap, err := getIPMap(common.HOST_TYPE_CONTROLLER)
	if err != nil {
		log.Error(err)
	}

	orgDB.Where("type != ?", common.VTAP_TYPE_TUNNEL_DECAPSULATION).Find(&vtaps)
	for _, vtap := range vtaps {
		// check vtap.controller_ip is not in controller.ip, set to empty if not exist
		if _, ok := ipMap[vtap.ControllerIP]; !ok {
			log.Infof("controller ip(%s) in vtap(%s) is invalid", vtap.ControllerIP, vtap.Name)
			vtap.ControllerIP = ""
			orgDB.Model(&mysql.VTap{}).Where("lcuuid = ?", vtap.Lcuuid).Update("controller_ip", "")
		}

		if vtap.ControllerIP == "" {
			noControllerVtapCount += 1
		} else if vtap.Exceptions&common.VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED != 0 {
			// 检查是否存在已分配控制器，但异常未清除的采集器
			exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED
			orgDB.Model(&vtap).Update("exceptions", exceptions)
		}
	}
	// 如果存在没有控制器的采集器，触发控制器重新分配
	if noControllerVtapCount > 0 {
		c.TriggerReallocController(orgDB, "")
	}
	log.Info("vtap controller check end")
}

func (c *ControllerCheck) vtapControllerAlloc(orgDB *mysql.DB, excludeIP string) {
	var vtaps []mysql.VTap
	var controllers []mysql.Controller
	var azs []mysql.AZ
	var azControllerConns []mysql.AZControllerConnection

	log.Info("vtap controller alloc start")

	orgDB.Where("type != ?", common.VTAP_TYPE_TUNNEL_DECAPSULATION).Find(&vtaps)
	orgDB.Where("state = ?", common.HOST_STATE_COMPLETE).Find(&controllers)

	// 获取待分配采集器对应的可用区信息
	// 获取控制器当前已分配的采集器个数
	azToNoControllerVTaps := make(map[string][]*mysql.VTap)
	controllerIPToUsedVTapNum := make(map[string]int)
	azLcuuids := mapset.NewSet()
	for i, vtap := range vtaps {
		if vtap.ControllerIP != "" && vtap.ControllerIP != excludeIP {
			controllerIPToUsedVTapNum[vtap.ControllerIP] += 1
			continue
		}
		azToNoControllerVTaps[vtap.AZ] = append(azToNoControllerVTaps[vtap.AZ], &vtaps[i])
		azLcuuids.Add(vtap.AZ)
	}
	// 获取控制器的剩余采集器个数
	controllerIPToAvailableVTapNum := make(map[string]int)
	for _, controller := range controllers {
		controllerIPToAvailableVTapNum[controller.IP] = controller.VTapMax
		if usedVTapNum, ok := controllerIPToUsedVTapNum[controller.IP]; ok {
			controllerIPToAvailableVTapNum[controller.IP] -= usedVTapNum
		}
	}

	// 根据可用区查询region信息
	orgDB.Where("lcuuid IN (?)", azLcuuids.ToSlice()).Find(&azs)
	regionToAZLcuuids := make(map[string][]string)
	regionLcuuids := mapset.NewSet()
	for _, az := range azs {
		regionToAZLcuuids[az.Region] = append(regionToAZLcuuids[az.Region], az.Lcuuid)
		regionLcuuids.Add(az.Region)
	}

	// 获取可用区中的控制器IP
	orgDB.Where("region IN (?)", regionLcuuids.ToSlice()).Find(&azControllerConns)
	azToControllerIPs := make(map[string][]string)
	for _, conn := range azControllerConns {
		if conn.AZ == "ALL" {
			if azLcuuids, ok := regionToAZLcuuids[conn.Region]; ok {
				for _, azLcuuid := range azLcuuids {
					azToControllerIPs[azLcuuid] = append(azToControllerIPs[azLcuuid], conn.ControllerIP)
				}
			}
		} else {
			azToControllerIPs[conn.AZ] = append(azToControllerIPs[conn.AZ], conn.ControllerIP)
		}
	}

	// 遍历待分配采集器，分配控制器IP
	for az, noControllerVtaps := range azToNoControllerVTaps {
		// 获取可分配的控制器列表
		controllerAvailableVTapNum := []common.KVPair{}
		if controllerIPs, ok := azToControllerIPs[az]; ok {
			for _, controllerIP := range controllerIPs {
				if availableVTapNum, ok := controllerIPToAvailableVTapNum[controllerIP]; ok {
					controllerAvailableVTapNum = append(
						controllerAvailableVTapNum,
						common.KVPair{Key: controllerIP, Value: availableVTapNum},
					)
				}
			}
		}

		for _, vtap := range noControllerVtaps {
			// 分配控制器失败，更新异常错误码
			if len(controllerAvailableVTapNum) == 0 {
				log.Warningf("no available controller for vtap (%s)", vtap.Name)
				exceptions := vtap.Exceptions | common.VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED
				orgDB.Model(&vtap).Update("exceptions", exceptions)
				continue
			}
			sort.Slice(controllerAvailableVTapNum, func(i, j int) bool {
				return controllerAvailableVTapNum[i].Value > controllerAvailableVTapNum[j].Value
			})
			// Search for controllers that have capacity. If none has capacity, the collector limit is allowed.
			// There are five types of Value in controllerAvailableVTapNum:
			// 1. All positive numbers
			// 2. Positive numbers and 0
			// 3. All are 0
			// 4, 0 and negative numbers
			// 5. All negative numbers
			controllerAvailableVTapNum[0].Value -= 1
			controllerIPToAvailableVTapNum[controllerAvailableVTapNum[0].Key] -= 1

			// 分配控制器成功，更新控制器IP + 清空控制器分配失败的错误码
			log.Infof("alloc controller (%s) for vtap (%s)", controllerAvailableVTapNum[0].Key, vtap.Name)
			orgDB.Model(&vtap).Update("controller_ip", controllerAvailableVTapNum[0].Key)
			if vtap.Exceptions&common.VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED != 0 {
				exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED
				orgDB.Model(&vtap).Update("exceptions", exceptions)
			}
		}
	}
	log.Info("vtap controller alloc end")
}

func (c *ControllerCheck) azConnectionCheck(orgDB *mysql.DB) {
	var azs []mysql.AZ
	var azControllerConns []mysql.AZControllerConnection

	log.Info("az connection check start")

	orgDB.Find(&azs)
	azLcuuidToName := make(map[string]string)
	for _, az := range azs {
		azLcuuidToName[az.Lcuuid] = az.Name
	}

	orgDB.Find(&azControllerConns)
	for _, conn := range azControllerConns {
		if conn.AZ == "ALL" {
			continue
		}
		if name, ok := azLcuuidToName[conn.AZ]; !ok {
			orgDB.Delete(&conn)
			log.Infof("delete controller (%s) az (%s) connection", conn.ControllerIP, name)
		}
	}
	log.Info("az connection check end")
}

func (c *ControllerCheck) cleanExceptionControllerData(orgDB *mysql.DB, controllerIPs []string) {
	if len(controllerIPs) == 0 {
		return
	}

	// delete genesis vinterface on invalid controller
	err := orgDB.Where("node_ip IN ?", controllerIPs).Delete(&model.GenesisVinterface{}).Error
	if err != nil {
		log.Errorf("clean controllers (%s) genesis vinterface failed: %s", controllerIPs, err)
	} else {
		log.Infof("clean controllers (%s) genesis vinterface success", controllerIPs)
	}
}

func (c *ControllerCheck) SyncDefaultOrgData() {
	var controllers []mysql.Controller
	if err := mysql.DefaultDB.Find(&controllers); err != nil {
		log.Error(err)
	}
	if err := mysql.SyncDefaultOrgData(controllers); err != nil {
		log.Error(err)
	}
}
