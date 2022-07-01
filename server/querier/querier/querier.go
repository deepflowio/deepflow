package querier

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/metaflowys/metaflow/server/libs/logger"
	"github.com/metaflowys/metaflow/server/querier/config"
	"github.com/metaflowys/metaflow/server/querier/router"
)

var log = logging.MustGetLogger("querier")

func Start(configPath string) {
	ServerCfg := config.DefaultConfig()
	ServerCfg.Load(configPath)
	config.Cfg = &ServerCfg.QuerierConfig
	cfg := ServerCfg.QuerierConfig
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Querier ==============================")
	log.Infof("querier config:\n%s", string(bytes))

	// engine加载数据库tag/metric等信息
	err := Load()
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	// 注册router
	r := gin.Default()
	r.Use(LoggerHandle)
	router.QueryRouter(r)
	// TODO: 增加router
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
		os.Exit(0)
	}
}

func LoggerHandle(c *gin.Context) {
	ip := c.ClientIP()          //请求ip
	method := c.Request.Method  // Method
	url := c.Request.RequestURI // url
	startTime := time.Now()
	defer func() {
		err := recover()
		if err != nil {
			log.Errorf("%13v | %15s | %s | %s |",
				time.Since(startTime), //执行时间
				ip,
				method,
				url,
			)
			log.Error(err)
			// 堆栈信息
			var buf [4096]byte
			n := runtime.Stack(buf[:], false)
			log.Error(string(buf[:n]))
		}
	}()
	// 处理请求
	c.Next()
	endTime := time.Now()
	log.Infof("| %3d | %13v | %15s | %s | %s |",
		c.Writer.Status(),      // 状态码
		endTime.Sub(startTime), //执行时间
		ip,
		method,
		url,
	)
}
