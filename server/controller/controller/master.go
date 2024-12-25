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

package controller

import (
	"context"
	"os"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator"
	"github.com/deepflowio/deepflow/server/controller/election"
	"github.com/deepflowio/deepflow/server/controller/http"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	resoureservice "github.com/deepflowio/deepflow/server/controller/http/service/resource"
	"github.com/deepflowio/deepflow/server/controller/monitor"
	"github.com/deepflowio/deepflow/server/controller/monitor/license"
	"github.com/deepflowio/deepflow/server/controller/monitor/vtap"
	"github.com/deepflowio/deepflow/server/controller/prometheus"
	"github.com/deepflowio/deepflow/server/controller/recorder"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
	tagrecordercheck "github.com/deepflowio/deepflow/server/controller/tagrecorder/check"
)

func IsMasterRegion(cfg *config.ControllerConfig) bool {
	if cfg.TrisolarisCfg.NodeType == "master" {
		return true
	}
	return false
}

// try to check until success
func IsMasterController(cfg *config.ControllerConfig) bool {
	if IsMasterRegion(cfg) {
		for range time.Tick(time.Second * 5) {
			isMasterController, err := election.IsMasterController()
			if err == nil {
				if isMasterController {
					return true
				} else {
					return false
				}
			} else {
				log.Errorf("check whether I am master controller failed: %s", err.Error())
			}
		}
	}
	return false
}

// migrate db by master region master controller
func migrateMySQL(cfg *config.ControllerConfig) {
	err := migrator.Migrate(cfg.MetadbCfg)
	if err != nil {
		log.Errorf("migrate metadb failed: %s", err.Error())
		time.Sleep(time.Second)
		os.Exit(0)
	}
}

func checkAndStartMasterFunctions(
	cfg *config.ControllerConfig, ctx context.Context,
	controllerCheck *monitor.ControllerCheck, analyzerCheck *monitor.AnalyzerCheck,
) {

	// 定时检查当前是否为master controller
	// 仅master controller才启动以下goroutine
	// - tagrecorder
	// - 控制器和数据节点检查
	// - license分配和检查
	// - resource id manager
	// - clean deleted/dirty resource data
	// - prometheus encoder
	// - prometheus app label layout updater
	// - http resource refresh task manager

	// 从区域控制器无需判断是否为master controller
	if !IsMasterRegion(cfg) {
		return
	}

	vtapCheck := vtap.NewVTapCheck(cfg.MonitorCfg, ctx)
	vtapRebalanceCheck := vtap.NewRebalanceCheck(cfg.MonitorCfg, ctx)
	vtapLicenseAllocation := license.NewVTapLicenseAllocation(cfg.MonitorCfg, ctx)
	recorderResource := recorder.GetResource()
	domainChecker := resoureservice.NewDomainCheck(ctx)
	prometheus := prometheus.GetSingleton()
	tagRecorder := tagrecorder.GetSingleton()
	tagrecordercheck.GetSingleton().Init(ctx, *cfg)
	tr := tagrecordercheck.GetSingleton()
	deletedORGChecker := service.GetDeletedORGChecker(ctx, cfg.FPermit)

	httpService := http.GetSingleton()

	var sCtx context.Context
	var sCancel context.CancelFunc

	masterController := ""
	thisIsMasterController := false
	for range time.Tick(time.Minute) {
		newThisIsMasterController, newMasterController, err := election.IsMasterControllerAndReturnIP()
		if err != nil {
			continue
		}
		if masterController != newMasterController {
			if newThisIsMasterController {
				thisIsMasterController = true
				log.Infof("I am the master controller now, previous master controller is %s", masterController)

				sCtx, sCancel = context.WithCancel(ctx)

				migrateMySQL(cfg)

				// 启动资源ID管理器
				err := recorderResource.IDManagers.Start(sCtx)
				if err != nil {
					log.Errorf("resource id manager start failed: %s", err.Error())
					time.Sleep(time.Second)
					os.Exit(0)
				}

				// 启动tagrecorder
				tagRecorder.UpdaterManager.Start(sCtx)
				tr.Check()

				// 控制器检查
				controllerCheck.Start(sCtx)

				// 数据节点检查
				analyzerCheck.Start(sCtx)

				// vtap check
				vtapCheck.Start(sCtx)

				// rebalance vtap check
				vtapRebalanceCheck.Start(sCtx)

				// license分配和检查
				if cfg.BillingMethod == common.BILLING_METHOD_LICENSE {
					vtapLicenseAllocation.Start(sCtx)
				}

				// 资源数据清理
				recorderResource.Cleaners.Start(sCtx)

				// domain检查及自愈
				domainChecker.Start(sCtx)

				prometheus.Encoders.Start(sCtx)
				// prometheus.APPLabelLayoutUpdater.Start()
				prometheus.Clear.Start(sCtx)

				if cfg.DFWebService.Enabled {
					httpService.TaskManager.Start(sCtx, cfg.FPermit, cfg.RedisCfg)
					deletedORGChecker.Start(sCtx)
				}
			} else if thisIsMasterController {
				thisIsMasterController = false
				log.Infof("I am not the master controller anymore, new master controller is %s", newMasterController)

				// stop tagrecorder
				// stop controller check
				// stop analyzer check
				// stop vtap check
				// stop vtap license allocation and check
				// stop domain checker
				// stop prometheus related
				// stop http task mananger
				// stop resource cleaner
				// stop delete org checker
				if sCancel != nil {
					sCancel()
				}

				recorderResource.IDManagers.Stop()
				prometheus.Encoders.Stop()
			} else {
				log.Infof(
					"current master controller is %s, previous master controller is %s",
					newMasterController, masterController,
				)
			}
		}
		masterController = newMasterController
	}
}

func checkAndStartAllRegionMasterFunctions(ctx context.Context) {
	var sCtx context.Context
	var sCancel context.CancelFunc

	tr := tagrecorder.GetSingleton()
	masterController := ""
	thisIsMasterController := false
	for range time.Tick(time.Minute) {
		newThisIsMasterController, newMasterController, err := election.IsMasterControllerAndReturnIP()
		if err != nil {
			continue
		}
		if masterController != newMasterController {
			if newThisIsMasterController {
				sCtx, sCancel = context.WithCancel(ctx)
				thisIsMasterController = true
				log.Infof("I am the master controller now, previous master controller is %s", masterController)
				go tr.Dictionary.Start(sCtx)
			} else if thisIsMasterController {
				thisIsMasterController = false
				log.Infof("I am not the master controller anymore, new master controller is %s", newMasterController)
			} else {
				log.Infof(
					"current master controller is %s, previous master controller is %s",
					newMasterController, masterController,
				)
				if sCancel != nil {
					sCancel()
				}
			}
		}
		masterController = newMasterController
	}
}
