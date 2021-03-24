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

	logging "github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/logger"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	yaml "gopkg.in/yaml.v2"

	"gitlab.x.lan/yunshan/droplet/config"
	dropletcfg "gitlab.x.lan/yunshan/droplet/droplet/config"
	"gitlab.x.lan/yunshan/droplet/droplet/droplet"
	"gitlab.x.lan/yunshan/droplet/droplet/profiler"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	rozecfg "gitlab.x.lan/yunshan/droplet/roze/config"
	"gitlab.x.lan/yunshan/droplet/roze/roze"
	streamcfg "gitlab.x.lan/yunshan/droplet/stream/config"
	"gitlab.x.lan/yunshan/droplet/stream/stream"
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
	if os.Getppid() != 1 {
		logger.EnableStdoutLog()
	}

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
	stats.SetRemotes(net.UDPAddr{net.ParseIP("127.0.0.1").To4(), INFLUXDB_RELAY_PORT, ""})

	dropletConfig := dropletcfg.Load(*configPath)
	bytes, _ = yaml.Marshal(dropletConfig)
	log.Infof("droplet config:\n%s", string(bytes))

	receiver := receiver.NewReceiver(datatype.DROPLET_PORT, cfg.UDPReadBuffer, cfg.TCPReadBuffer)
	receiver.Start()

	closers := droplet.Start(dropletConfig, receiver)

	if cfg.StreamRozeEnabled {
		streamConfig := streamcfg.Load(*configPath)
		bytes, _ = yaml.Marshal(streamConfig)
		log.Infof("stream config:\n%s", string(bytes))

		rozeConfig := rozecfg.Load(*configPath)
		bytes, _ = yaml.Marshal(rozeConfig)
		log.Infof("roze config:\n%s", string(bytes))

		roze, err := roze.NewRoze(rozeConfig, receiver)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		roze.Start()
		defer roze.Close()

		stream := stream.NewStream(streamConfig, receiver)
		stream.Start()
		defer stream.Close()
	}

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
