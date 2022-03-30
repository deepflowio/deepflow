package querier

import (
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	"gopkg.in/yaml.v2"

	"gitlab.yunshan.net/yunshan/droplet-libs/logger"
	"metaflow/querier/config"
	"metaflow/querier/router"
)

var log = logging.MustGetLogger("querier")
var configPath = flag.String("f", "/etc/querier.yaml", "specify config file location")

type Controller struct{}

func Start() {
	// 加载配置文件
	cfg := config.DefaultConfig()
	config.Cfg = cfg
	cfg.Load(*configPath)
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Querier ==============================")
	log.Infof("querier config:\n%s", string(bytes))

	// engine加载数据库tag/metric等信息
	Load()
	// 注册router
	r := gin.Default()
	router.QueryRouter(r)
	// TODO: 增加router
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
	}
}
