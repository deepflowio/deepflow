package droplet

import (
	"errors"
	"io"
	"net"
	_ "net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/logger"
	libqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gopkg.in/yaml.v2"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/flowgenerator"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/mapreduce"
	"gitlab.x.lan/yunshan/droplet/pcap"
	"gitlab.x.lan/yunshan/droplet/profiler"
	"gitlab.x.lan/yunshan/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/sender"
	"gitlab.x.lan/yunshan/message/trident"
)

var log = logging.MustGetLogger("droplet")

const (
	INFLUXDB_RELAY_PORT = 20048
	DEBUG_LISTEN_IP     = "127.0.0.1"
	DEBUG_LISTEN_PORT   = 9527
)

func getLocalIp() (net.IP, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ip := net.ParseIP(addr).To4(); ip != nil {
			return ip, nil
		}
	}
	return nil, errors.New("Unable to resolve local ip by hostname")
}

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
		controllers[i] = net.ParseIP(ipString).To4()
	}
	synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.ControllerPort, cfg.RpcTimeout)
	synchronizer.Start()

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}
	// L1 - packet source from tridentAdapter
	manager := queue.NewManager()
	releaseMetaPacketBlock := func(x interface{}) {
		datatype.ReleaseMetaPacketBlock(x.(*datatype.MetaPacketBlock))
	}
	flowGeneratorQueues := manager.NewQueues(
		"1-meta-packet-block-to-flow-generator", cfg.Queue.FlowGeneratorQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second), libqueue.OptionRelease(releaseMetaPacketBlock),
	)

	tridentAdapter := adapter.NewTridentAdapter(flowGeneratorQueues.Writers(), cfg.Adapter.SocketBufferSize, cfg.Adapter.OrderingCacheSize)
	if tridentAdapter == nil {
		return
	}

	localIp, err := getLocalIp()
	if err != nil {
		log.Error(err)
		return
	} else if localIp.String() == "127.0.0.1" {
		log.Error("Invalid ip resolved by hostname")
		os.Exit(1)
	}

	// labeler
	labelerManager := labeler.NewLabelerManager(
		cfg.Queue.PacketQueueCount, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable, cfg.Labeler.FirstPathDdbsDisable)
	synchronizer.Register(func(response *trident.SyncResponse, version *config.RpcInfoVersions) {
		log.Debug(response, version)
		// Labeler更新策略信息
		labelerManager.OnAclDataChange(response)
	})
	labelerManager.Start()

	// L3 - flow generator & metering marshaller & pcap
	docsInBuffer := int(cfg.Queue.DocQueueSize)
	windowSize := int(cfg.MapReduce.WindowSize)
	windowMoveMargin := int(cfg.MapReduce.WindowMoveMargin)
	flowFlushInterval := time.Second * 5
	releaseTaggedFlow := func(x interface{}) {
		datatype.ReleaseTaggedFlow(x.(*datatype.TaggedFlow))
	}
	pcapAppQueues := manager.NewQueues(
		"2-meta-packet-block-to-pcap-app", cfg.Queue.PCapAppQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second*10), libqueue.OptionRelease(releaseMetaPacketBlock),
	)
	flowDuplicatorQueues := manager.NewQueues(
		"2-tagged-flow-to-flow-duplicator", cfg.Queue.FlowDuplicatorQueueSize, cfg.Queue.PacketQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionRelease(releaseTaggedFlow))
	meteringAppQueues := manager.NewQueues(
		"2-mini-tagged-flow-to-metering-app", cfg.Queue.MeteringAppQueueSize, cfg.Queue.PacketQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionFlushIndicator(flowFlushInterval), libqueue.OptionRelease(releaseTaggedFlow),
	)

	flowgenerator.SetFlowGenerator(cfg)
	timeoutConfig := flowgenerator.TimeoutConfig{
		Opening:         cfg.FlowGenerator.OthersTimeout,
		Established:     cfg.FlowGenerator.EstablishedTimeout,
		Closing:         cfg.FlowGenerator.OthersTimeout,
		EstablishedRst:  cfg.FlowGenerator.ClosingRstTimeout,
		Exception:       cfg.FlowGenerator.OthersTimeout,
		ClosedFin:       0,
		SingleDirection: cfg.FlowGenerator.OthersTimeout,
	}
	flowgenerator.SetTimeout(timeoutConfig)
	flowLimitNum := int(cfg.FlowGenerator.FlowCountLimit) / cfg.Queue.PacketQueueCount
	policyGetter := func(meta *datatype.MetaPacket, threadIndex int) {
		labelerManager.GetPolicy(meta, threadIndex)
	}
	for i := 0; i < cfg.Queue.PacketQueueCount; i++ {
		flowGenerator := flowgenerator.New(
			policyGetter, flowGeneratorQueues.Readers()[i],
			pcapAppQueues.Writers()[i], meteringAppQueues.Writers()[i],
			flowDuplicatorQueues.Writers()[i], flowLimitNum, i, flowFlushInterval)
		flowGenerator.Start()
	}

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
		cfg.PCap.MaxFileKeepDay,
		cfg.PCap.FileDirectory,
	).Start()
	closers = append(closers, pcapClosers...)

	// L4 - metering app
	meteringDocMarshallerQueue := manager.NewQueues(
		"3-metering-doc-to-marshaller",
		cfg.Queue.MeteringDocMarshallerQueueSize, cfg.Queue.DocQueueCount,
		cfg.Queue.PacketQueueCount,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)
	mapreduce.NewMeteringMapProcess(
		meteringDocMarshallerQueue.Writers(), meteringAppQueues.Readers(),
		docsInBuffer/int(cfg.Queue.PacketQueueCount), windowSize, windowMoveMargin).Start()

	// L4 - flow duplicator: flow app & flow marshaller
	flowAppQueues := manager.NewQueues(
		"3-tagged-flow-to-flow-app", cfg.Queue.FlowAppQueueSize, cfg.Queue.FlowQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionFlushIndicator(flowFlushInterval), libqueue.OptionRelease(releaseTaggedFlow))
	flowThrottleQueues := manager.NewQueues(
		"3-tagged-flow-to-flow-throttle", cfg.Queue.FlowThrottleQueueSize, cfg.Queue.FlowQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionRelease(releaseTaggedFlow))
	// 特殊处理：Duplicator的数量特意设置为PacketQueueCount，使得FlowGenerator所在环境均为单生产单消费
	for i := 0; i < cfg.Queue.PacketQueueCount; i++ {
		flowDuplicator := queue.NewDuplicator(i, 1024, flowDuplicatorQueues.Readers()[i], datatype.PseudoCloneTaggedFlowHelper)
		flowDuplicator.AddMultiQueue(flowAppQueues).AddMultiQueue(flowThrottleQueues).Start()
	}

	// L5 - flow sender
	flowSenderQueue := manager.NewQueue(
		"4-tagged-flow-to-flow-sender", cfg.Queue.FlowSenderQueueSize, libqueue.OptionRelease(releaseTaggedFlow))
	sender.NewFlowSender(
		flowThrottleQueues.Readers(), flowSenderQueue, flowSenderQueue,
		cfg.Stream, cfg.StreamPort, cfg.FlowThrottle, cfg.Queue.FlowSenderQueueSize).Start()

	// L5 - flow app
	flowDocMarshallerQueue := manager.NewQueues(
		"4-flow-doc-to-marshaller",
		cfg.Queue.FlowDocMarshallerQueueSize, cfg.Queue.DocQueueCount,
		cfg.Queue.FlowQueueCount,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)
	mapreduce.NewFlowMapProcess(
		flowDocMarshallerQueue.Writers(), flowAppQueues.Readers(),
		docsInBuffer/int(cfg.Queue.FlowQueueCount), windowSize, windowMoveMargin).Start()

	// L6 - flow/metering doc sender
	builder := sender.NewZeroDocumentSenderBuilder()
	builder.AddQueue(meteringDocMarshallerQueue.Readers())
	builder.AddQueue(flowDocMarshallerQueue.Readers())
	builder.AddListenPorts(cfg.ZeroPort)
	builder.Build().Start(cfg.Queue.DocSenderQueueSize)

	// 其他所有组件启动完成以后运行TridentAdapter，尽量避免启动过程中队列丢包
	tridentAdapter.Start()
	return
}
