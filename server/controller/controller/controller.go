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

package controller

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/db/redis"
	"github.com/deepflowys/deepflow/server/controller/election"
	"github.com/deepflowys/deepflow/server/controller/genesis"
	"github.com/deepflowys/deepflow/server/controller/grpc"
	"github.com/deepflowys/deepflow/server/controller/manager"
	"github.com/deepflowys/deepflow/server/controller/monitor"
	"github.com/deepflowys/deepflow/server/controller/monitor/license"
	"github.com/deepflowys/deepflow/server/controller/recorder"
	"github.com/deepflowys/deepflow/server/controller/report"
	"github.com/deepflowys/deepflow/server/controller/router"
	"github.com/deepflowys/deepflow/server/controller/service"
	"github.com/deepflowys/deepflow/server/controller/statsd"
	"github.com/deepflowys/deepflow/server/controller/tagrecorder"
	"github.com/deepflowys/deepflow/server/controller/trisolaris"
	trouter "github.com/deepflowys/deepflow/server/controller/trisolaris/server/http"

	_ "github.com/deepflowys/deepflow/server/controller/grpc/controller"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/grpc/healthcheck"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/grpc/synchronize"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/http/cache"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/http/upgrade"
)

var log = logging.MustGetLogger("controller")

type Controller struct{}

func Start(ctx context.Context, configPath string) {
	flag.Parse()

	serverCfg := config.DefaultConfig()
	serverCfg.Load(configPath)
	cfg := &serverCfg.ControllerConfig
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Controller ==============================")
	log.Infof("controller config:\n%s", string(bytes))
	setGlobalConfig(cfg)

	// register router
	r := gin.Default()
	router.HealthRouter(r)
	go func() {
		if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
			log.Errorf("startup service failed, err:%v\n", err)
			time.Sleep(time.Second)
			os.Exit(0)
		}
	}()
	defer router.SetInitStageForHealthChecker(router.OK)

	// start election
	go election.Start(ctx, cfg)

	isMasterController := IsMasterController(cfg)
	if isMasterController {
		router.SetInitStageForHealthChecker("MySQL migration")
		migrateDB(cfg)
	}

	router.SetInitStageForHealthChecker("MySQL init")
	// 初始化MySQL
	mysql.Db = mysql.Gorm(cfg.MySqlCfg)
	if mysql.Db == nil {
		log.Error("connect mysql failed")
		time.Sleep(time.Second)
		os.Exit(0)
	}

	// TODO move to goroutine
	// 启动资源ID管理器
	if _, enabled := os.LookupEnv("FEATURE_FLAG_ALLOCATE_ID"); enabled {
		if isMasterController {
			router.SetInitStageForHealthChecker("Resource ID manager init")
			startResourceIDManager(cfg)
		}
	}

	// 初始化Redis
	if cfg.RedisCfg.Enabled && cfg.TrisolarisCfg.NodeType == "master" {
		router.SetInitStageForHealthChecker("Redis init")

		err := redis.InitRedis(cfg.RedisCfg)
		if err != nil {
			log.Error("connect redis failed")
			time.Sleep(time.Second)
			os.Exit(0)
		}
	}

	router.SetInitStageForHealthChecker("Statsd init")
	// start statsd
	err := statsd.NewStatsdMonitor(cfg.StatsdCfg)
	if err != nil {
		log.Error("cloud statsd connect telegraf failed")
		time.Sleep(time.Second)
		os.Exit(0)
	}

	router.SetInitStageForHealthChecker("Genesis init")
	// 启动genesis
	g := genesis.NewGenesis(cfg)
	g.Start()

	router.SetInitStageForHealthChecker("Manager init")
	// 启动resource manager
	// 每个云平台启动一个cloud和recorder
	m := manager.NewManager(cfg.ManagerCfg)
	m.Start()

	router.SetInitStageForHealthChecker("Trisolaris init")
	// 启动trisolaris
	t := trisolaris.NewTrisolaris(&cfg.TrisolarisCfg, mysql.Db)
	go t.Start()

	router.SetInitStageForHealthChecker("TagRecorder init")
	tr := tagrecorder.NewTagRecorder(*cfg)
	go tr.StartChDictionaryUpdate()

	controllerCheck := monitor.NewControllerCheck(cfg)
	analyzerCheck := monitor.NewAnalyzerCheck(cfg)
	vtapCheck := monitor.NewVTapCheck(cfg.MonitorCfg)
	go func() {
		// 定时检查当前是否为master controller
		// 仅master controller才启动以下goroutine
		// - tagrecorder
		// - 控制器和数据节点检查
		// - license分配和检查
		// 除非进程重启，才会出现master controller切换的情况，所以暂时无需进行goroutine的停止

		// 从区域控制器无需判断是否为master controller
		if cfg.TrisolarisCfg.NodeType != "master" {
			return
		}
		vtapLicenseAllocation := license.NewVTapLicenseAllocation(cfg.MonitorCfg)
		masterController := ""
		// TODO start as soon as possible
		for range time.Tick(time.Minute) {
			isMasterController, curMasterController, err := election.IsMasterControllerAndReturnIP()
			if err != nil {
				continue
			}
			if masterController != curMasterController {
				log.Infof("current master controller is %s", curMasterController)
				masterController = curMasterController
				if isMasterController {
					// 启动资源ID管理器
					startResourceIDManager(cfg)

					// 启动tagrecorder
					tr.Start()

					// 控制器检查
					controllerCheck.Start()

					// 数据节点检查
					analyzerCheck.Start()

					// vtap check
					vtapCheck.Start()

					// license分配和检查
					vtapLicenseAllocation.Start()

					// 启动软删除数据清理
					recorder.TimedCleanDeletedResources(
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceCleanInterval),
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceRetentionTime),
					)

					if _, enabled := os.LookupEnv("FEATURE_FLAG_CHECK_DOMAIN_CONTROLLER"); enabled {
						// 自动切换domain控制器
						service.TimedCheckDomain()
					}
				}
			}
		}
	}()

	router.SetInitStageForHealthChecker("Register routers init")
	router.ElectionRouter(r)
	router.DebugRouter(r, m, g)
	router.ControllerRouter(r, controllerCheck, cfg)
	router.AnalyzerRouter(r, analyzerCheck, cfg)
	router.VtapRouter(r)
	router.VtapGroupRouter(r, cfg)
	router.DataSourceRouter(r, cfg)
	router.DomainRouter(r, cfg)
	router.VTapGroupConfigRouter(r)
	router.VTapInterface(r, cfg)
	router.VPCRouter(r)
	trouter.RegistRouter(r)

	grpcStart(ctx, cfg)

	if !cfg.ReportingDisabled {
		go report.NewReportServer(mysql.Db).StartReporting()
	}
}

func grpcStart(ctx context.Context, cfg *config.ControllerConfig) {
	go grpc.Run(ctx, cfg)
}

func setGlobalConfig(cfg *config.ControllerConfig) {
	grpcPort, err := strconv.Atoi(cfg.GrpcPort)
	if err != nil {
		log.Error("config grpc-port is not a port")
		time.Sleep(time.Second)
		os.Exit(0)
	}
	grpcNodePort, err := strconv.Atoi(cfg.GrpcNodePort)
	if err != nil {
		log.Error("config grpc-node-port is not a port")
		time.Sleep(time.Second)
		os.Exit(0)
	}
	common.GConfig = &common.GlobalConfig{
		HTTPPort:     cfg.ListenPort,
		HTTPNodePort: cfg.ListenNodePort,
		GRPCPort:     grpcPort,
		GRPCNodePort: grpcNodePort,
	}
}
