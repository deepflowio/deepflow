package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"server/ingester/ckmonitor"
	"server/ingester/datasource"
	"server/libs/datatype"
	"server/libs/debug"
	"server/libs/logger"
	"server/libs/receiver"
	"server/libs/stats"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"server/ingester/ckissu"
	"server/ingester/config"
	dropletcfg "server/ingester/droplet/config"
	"server/ingester/droplet/droplet"
	"server/ingester/droplet/profiler"
	"server/ingester/dropletctl"
	extmetricscfg "server/ingester/ext_metrics/config"
	"server/ingester/ext_metrics/ext_metrics"
	rozecfg "server/ingester/roze/config"
	"server/ingester/roze/roze"
	streamcfg "server/ingester/stream/config"
	"server/ingester/stream/stream"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var configPath = flag.String("f", "/etc/droplet.yaml", "Specify config file location")
var version = flag.Bool("v", false, "Display the version")

var RevCount, Revision, CommitDate, goVersion string

const (
	INFLUXDB_RELAY_PORT = 20048
	PROFILER_PORT       = 9526
)

func main() {
	logger.EnableStdoutLog()

	flag.Parse()
	if *version {
		fmt.Printf("%s %s %s\n%s\n", RevCount, Revision, CommitDate, goVersion)
		os.Exit(0)
	}

	cfg := config.Load(*configPath)
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Droplet ==============================")
	log.Infof("base config:\n%s", string(bytes))

	debug.SetIpAndPort(dropletctl.DEBUG_LISTEN_IP, dropletctl.DEBUG_LISTEN_PORT)
	debug.NewLogLevelControl()

	profiler := profiler.NewProfiler(PROFILER_PORT)
	if cfg.Profiler {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		profiler.Start()
	}

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}

	stats.RegisterGcMonitor()
	stats.SetMinInterval(10 * time.Second)
	stats.SetRemotes(net.JoinHostPort(cfg.Influxdb.Host, cfg.Influxdb.Port))

	dropletConfig := dropletcfg.Load(*configPath)
	bytes, _ = yaml.Marshal(dropletConfig)
	log.Infof("droplet config:\n%s", string(bytes))

	receiver := receiver.NewReceiver(datatype.DROPLET_PORT, cfg.UDPReadBuffer, cfg.TCPReadBuffer)

	closers := droplet.Start(dropletConfig, receiver)

	if cfg.StreamRozeEnabled {
		streamConfig := streamcfg.Load(*configPath)
		bytes, _ = yaml.Marshal(streamConfig)
		log.Infof("stream config:\n%s", string(bytes))

		rozeConfig := rozecfg.Load(*configPath)
		bytes, _ = yaml.Marshal(rozeConfig)
		log.Infof("roze config:\n%s", string(bytes))

		extMetricsConfig := extmetricscfg.Load(*configPath)
		bytes, _ = yaml.Marshal(extMetricsConfig)
		log.Infof("ext_metrics config:\n%s", string(bytes))

		// 写遥测数据
		roze, err := roze.NewRoze(rozeConfig, receiver)
		checkError(err)
		roze.Start()
		defer roze.Close()

		// 写流日志数据
		stream, err := stream.NewStream(streamConfig, receiver)
		checkError(err)
		stream.Start()
		defer stream.Close()

		// 写ext_metrics数据
		extMetrics, err := ext_metrics.NewExtMetrics(extMetricsConfig, receiver)
		checkError(err)
		extMetrics.Start()
		defer extMetrics.Close()

		// 创建、修改、删除数据源及其存储时长
		ds := datasource.NewDatasourceManager([]string{rozeConfig.CKDB.Primary, rozeConfig.CKDB.Secondary},
			rozeConfig.CKDBAuth.Username, rozeConfig.CKDBAuth.Password, rozeConfig.CKReadTimeout, rozeConfig.ReplicaEnabled,
			cfg.CKS3Storage.Enabled, cfg.CKS3Storage.Volume, cfg.CKS3Storage.TTLTimes)
		ds.Start()
		defer ds.Close()

		// 检查clickhouse的磁盘空间占用，达到阈值时，自动删除老数据
		cm, err := ckmonitor.NewCKMonitor(&cfg.CKDiskMonitor, rozeConfig.CKDB.Primary, rozeConfig.CKDB.Secondary, rozeConfig.CKDBAuth.Username, rozeConfig.CKDBAuth.Password)
		checkError(err)
		cm.Start()
		defer cm.Close()

		// clickhouse表结构变更处理
		issu, err := ckissu.NewCKIssu(rozeConfig.CKDB.Primary, rozeConfig.CKDB.Secondary, rozeConfig.CKDBAuth.Username, rozeConfig.CKDBAuth.Password)
		checkError(err)
		// 等roze,stream初始化建表完成,再执行issu
		time.Sleep(time.Second)
		err = issu.Start()
		checkError(err)
		issu.Close()
	}
	// receiver后启动，防止启动后收到数据无法处理，而上报异常日志
	receiver.Start()

	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
	log.Info("Gracefully stopping")
	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for _, closer := range closers {
		go func(c io.Closer) {
			c.Close()
			wg.Done()
		}(closer)
	}
	wg.Wait()
	receiver.Close()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
