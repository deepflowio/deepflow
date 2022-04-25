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
	"os"
	"runtime"
	"time"
)

var log = logging.MustGetLogger("querier")
var configPath = flag.String("f", "/etc/querier.yaml", "specify config file location")
var format = logging.MustStringFormatter(
	`%{time:2006-01-02 15:04:05.000} [%{level:.4s}] [%{module}] %{shortfile} %{message}`,
)

func Start() {
	flag.Parse()
	// 加载配置文件
	cfg := config.DefaultConfig()
	config.Cfg = cfg
	cfg.Load(*configPath)
	if os.Getppid() != 1 {
		logger.EnableStdoutLog()
	}
	logFormat := logging.AddModuleLevel(
		logging.NewBackendFormatter(
			logging.NewLogBackend(os.Stderr, "", 0),
			format,
		),
	)
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	logging.SetBackend(logFormat)
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Querier ==============================")
	log.Infof("querier config:\n%s", string(bytes))

	// engine加载数据库tag/metric等信息
	err := Load()
	if err != nil {
		log.Panic(err)
	}
	// 注册router
	r := gin.Default()
	r.Use(LoggerHandle)
	router.QueryRouter(r)
	// TODO: 增加router
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
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
