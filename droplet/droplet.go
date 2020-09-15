package droplet

import (
	"io"
	"net"
	_ "net/http/pprof"
	"runtime"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/logger"
	libpcap "gitlab.x.lan/yunshan/droplet-libs/pcap"
	libqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gopkg.in/yaml.v2"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/pcap"
	"gitlab.x.lan/yunshan/droplet/profiler"
	"gitlab.x.lan/yunshan/droplet/queue"
	"gitlab.x.lan/yunshan/message/trident"
)

var log = logging.MustGetLogger("droplet")

const (
	INFLUXDB_RELAY_PORT = 20048
	DEBUG_LISTEN_IP     = "127.0.0.1"
	DEBUG_LISTEN_PORT   = 9527
)

func Start(configPath string) (closers []io.Closer) {
	cfg := config.Load(configPath)
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	debug.SetIpAndPort(DEBUG_LISTEN_IP, DEBUG_LISTEN_PORT)
	bytes, _ := yaml.Marshal(cfg)
	log.Infof("droplet config:\n%s", string(bytes))
	profiler := profiler.NewProfiler(8000)

	if cfg.Profiler {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		profiler.Start()
	}

	stats.RegisterGcMonitor()
	stats.SetMinInterval(10 * time.Second)
	stats.SetRemotes(net.UDPAddr{net.ParseIP("127.0.0.1").To4(), INFLUXDB_RELAY_PORT, ""})

	controllers := make([]net.IP, len(cfg.ControllerIps))
	for i, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		if ipv4 := ip.To4(); ipv4 == nil {
			controllers[i] = ip
		} else {
			controllers[i] = ipv4
		}
	}
	synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.ControllerPort, cfg.RpcTimeout)
	synchronizer.Start()

	cleaner := libpcap.NewCleaner(5*time.Minute, int64(cfg.PCap.MaxDirectorySizeGB)<<30, int64(cfg.PCap.DiskFreeSpaceMarginGB)<<30, cfg.PCap.FileDirectory)
	cleaner.Start()

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}
	// L1 - packet source from tridentAdapter
	manager := queue.NewManager()
	releaseMetaPacketBlock := func(x interface{}) {
		datatype.ReleaseMetaPacketBlock(x.(*datatype.MetaPacketBlock))
	}
	labelerQueues := manager.NewQueues(
		"1-meta-packet-block-to-labeler", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionRelease(releaseMetaPacketBlock),
	)

	tridentAdapter := adapter.NewTridentAdapter(labelerQueues.Writers(), cfg.Adapter.SocketBufferSize, cfg.Adapter.OrderingCacheSize)
	if tridentAdapter == nil {
		return
	}

	pcapAppQueues := manager.NewQueues(
		"2-meta-packet-block-to-pcap-app", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second*10), libqueue.OptionRelease(releaseMetaPacketBlock),
	)

	// labeler
	labelerManager := labeler.NewLabelerManager(labelerQueues.Readers(), pcapAppQueues.Writers(),
		cfg.Queue.PacketQueueCount, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable)
	synchronizer.Register(func(response *trident.SyncResponse, version *config.RpcInfoVersions) {
		log.Debug(response, version)
		cleaner.UpdatePcapDataRetention(time.Duration(response.Config.GetPcapDataRetention()) * time.Hour * 24)
		// Labeler更新策略信息
		labelerManager.OnAclDataChange(response)
	})
	labelerManager.Start()

	pcapClosers := pcap.NewWorkerManager(
		pcapAppQueues.Readers(),
		pcapAppQueues.Writers(),
		cfg.PCap.TCPIPChecksum,
		cfg.PCap.BlockSizeKB,
		cfg.PCap.MaxConcurrentFiles,
		cfg.PCap.MaxFileSizeMB,
		cfg.PCap.MaxFilePeriodSecond,
		cfg.PCap.MaxDirectorySizeGB,
		cfg.PCap.DiskFreeSpaceMarginGB,
		cfg.PCap.FileDirectory,
	).Start()
	closers = append(closers, pcapClosers...)
	// 其他所有组件启动完成以后运行TridentAdapter，尽量避免启动过程中队列丢包
	tridentAdapter.Start()
	return
}
