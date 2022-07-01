package controller

import (
	"flag"
	"os"
	"time"

	"github.com/metaflowys/metaflow/server/libs/logger"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/config"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/db/redis"
	"github.com/metaflowys/metaflow/server/controller/genesis"
	"github.com/metaflowys/metaflow/server/controller/manager"
	"github.com/metaflowys/metaflow/server/controller/monitor"
	"github.com/metaflowys/metaflow/server/controller/monitor/license"
	"github.com/metaflowys/metaflow/server/controller/recorder"
	"github.com/metaflowys/metaflow/server/controller/router"
	"github.com/metaflowys/metaflow/server/controller/statsd"
	"github.com/metaflowys/metaflow/server/controller/tagrecorder"
	"github.com/metaflowys/metaflow/server/controller/trisolaris"

	_ "github.com/metaflowys/metaflow/server/controller/trisolaris/services/grpc/healthcheck"
	_ "github.com/metaflowys/metaflow/server/controller/trisolaris/services/grpc/synchronize"
	_ "github.com/metaflowys/metaflow/server/controller/trisolaris/services/http/cache"
	_ "github.com/metaflowys/metaflow/server/controller/trisolaris/services/http/health"
	_ "github.com/metaflowys/metaflow/server/controller/trisolaris/services/http/upgrade"
)

var log = logging.MustGetLogger("controller")

type Controller struct{}

func Start(configPath string) {
	flag.Parse()
	logger.EnableStdoutLog()

	serverCfg := config.DefaultConfig()
	serverCfg.Load(configPath)
	cfg := &serverCfg.ControllerConfig
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Controller ==============================")
	log.Infof("controller config:\n%s", string(bytes))

	// 初始化MySQL
	mysql.Db = mysql.Gorm(cfg.MySqlCfg)
	if mysql.Db == nil {
		log.Error("connect mysql failed")
		os.Exit(0)
	}

	// 初始化Redis
	err := redis.InitRedis(cfg.RedisCfg)
	if err != nil {
		log.Error("connect redis failed")
	}

	// start statsd
	err = statsd.NewStatsdMonitor(cfg.StatsdCfg)
	if err != nil {
		log.Error("cloud statsd connect telegraf failed")
		return
	}

	// 启动genesis
	g := genesis.NewGenesis(cfg.GenesisCfg)
	g.Start()

	// 启动resource manager
	// 每个云平台启动一个cloud和recorder
	m := manager.NewManager(cfg.ManagerCfg)
	m.Start()

	// 启动trisolaris
	t := trisolaris.NewTrisolaris(&cfg.TrisolarisCfg, mysql.Db)
	go t.Start()

	tr := tagrecorder.NewTagRecorder(*cfg)
	controllerCheck := monitor.NewControllerCheck(cfg.MonitorCfg)
	analyzerCheck := monitor.NewAnalyzerCheck(cfg.MonitorCfg)
	vtapLicenseAllocation := license.NewVTapLicenseAllocation(cfg.MonitorCfg)
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
		masterController := ""
		for range time.Tick(time.Minute) {
			isMasterController, curMasterController, err := common.IsMasterController()
			if err != nil {
				continue
			}
			if masterController != curMasterController {
				log.Infof("current master controller is %s", curMasterController)
				masterController = curMasterController
				if isMasterController {
					// 启动tagrecorder
					tr.Start()

					// 控制器检查
					controllerCheck.Start()

					// 数据节点检查
					analyzerCheck.Start()

					// license分配和检查
					vtapLicenseAllocation.Start()

					// 启动软删除数据清理
					recorder.CleanDeletedResources(
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceCleanInterval),
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceRetentionTime),
					)
				}
			}
		}
	}()

	// register router
	r := gin.Default()
	router.DebugRouter(r, m, g)
	router.HealthRouter(r)
	router.ControllerRouter(r, controllerCheck, cfg)
	router.AnalyzerRouter(r, analyzerCheck, cfg)
	router.VtapRouter(r)
	router.VtapGroupRouter(r, cfg)
	router.DataSourceRouter(r, cfg)
	router.DomainRouter(r)
	router.VTapGroupConfigRouter(r)
	router.VTapInterface(r, cfg)
	if err := r.Run(":20417"); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
		os.Exit(0)
	}
}
