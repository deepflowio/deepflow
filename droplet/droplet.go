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
	"gitlab.x.lan/yunshan/droplet-libs/utils"
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
	releaseMetaPacket := func(x interface{}) {
		datatype.ReleaseMetaPacket(x.(*datatype.MetaPacket))
	}
	labelerQueues := manager.NewQueues(
		"1-meta-packet-to-labeler", cfg.Queue.LabelerQueueSize, cfg.Queue.PacketQueueCount, 1,
		releaseMetaPacket,
	)

	tridentAdapter := adapter.NewTridentAdapter(labelerQueues, cfg.Adapter.SocketBufferSize, cfg.Adapter.OrderingCacheSize)
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

	// L2 - packet labeler
	flowGeneratorQueues := manager.NewQueues(
		"2-meta-packet-to-flow-generator", cfg.Queue.FlowGeneratorQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(cfg.FlowGenerator.FlowCleanInterval*time.Second), releaseMetaPacket,
	)
	pcapAppQueues := manager.NewQueues(
		"2-meta-packet-to-pcap-app", cfg.Queue.PCapAppQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second*10), releaseMetaPacket,
	)
	labelerManager := labeler.NewLabelerManager(
		labelerQueues.Readers(), cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable, cfg.Labeler.FirstPathDdbsDisable)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_FLOW, flowGeneratorQueues.Writers())
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_PCAP, pcapAppQueues.Writers())
	synchronizer.Register(func(response *trident.SyncResponse) {
		log.Debug(response)
		// Labeler更新策略信息
		labelerManager.OnAclDataChange(response)
	})
	labelerManager.Start()

	// L3 - flow generator & metering marshaller & pcap
	docsInBuffer := int(cfg.Queue.DocQueueSize)
	windowSize := int(cfg.MapReduce.WindowSize)
	windowMoveMargin := int(cfg.MapReduce.WindowMoveMargin)
	releaseTaggedFlow := func(x interface{}) {
		datatype.ReleaseTaggedFlow(x.(*datatype.TaggedFlow))
	}
	flowDuplicatorQueues := manager.NewQueues(
		"3-tagged-flow-to-flow-duplicator", cfg.Queue.FlowDuplicatorQueueSize, cfg.Queue.PacketQueueCount,
		cfg.Queue.PacketQueueCount, releaseTaggedFlow)
	meteringAppQueues := manager.NewQueues(
		"3-meta-packet-to-metering-app", cfg.Queue.MeteringAppQueueSize, cfg.Queue.PacketQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionFlushIndicator(time.Second*5), releaseMetaPacket,
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
	bufferSize := cfg.Queue.FlowGeneratorQueueSize / cfg.Queue.PacketQueueCount
	flowLimitNum := cfg.FlowGenerator.FlowCountLimit / int32(cfg.Queue.PacketQueueCount)
	if bufferSize > 8192 {
		bufferSize = 8192
	}
	for i := 0; i < cfg.Queue.PacketQueueCount; i++ {
		flowGenerator := flowgenerator.New(
			flowGeneratorQueues.Readers()[i], meteringAppQueues.Writers()[i],
			flowDuplicatorQueues.Writers()[i], bufferSize, flowLimitNum, i)
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
		"4-metering-doc-to-marshaller",
		cfg.Queue.MeteringDocMarshallerQueueSize, cfg.Queue.DocQueueCount,
		cfg.Queue.PacketQueueCount,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)
	mapreduce.NewMeteringMapProcess(
		meteringDocMarshallerQueue.Writers(), meteringAppQueues.Readers(),
		docsInBuffer/int(cfg.Queue.PacketQueueCount), windowSize, windowMoveMargin).Start()

	// L4 - flow duplicator: flow app & flow marshaller
	flowAppQueues := manager.NewQueues(
		"4-tagged-flow-to-flow-app", cfg.Queue.FlowAppQueueSize, cfg.Queue.FlowQueueCount,
		cfg.Queue.PacketQueueCount, libqueue.OptionFlushIndicator(time.Second*10), releaseTaggedFlow)
	flowMarshallerQueues := manager.NewQueues(
		"4-tagged-flow-to-flow-marshaller", cfg.Queue.FlowMarshallerQueueSize, cfg.Queue.FlowQueueCount,
		cfg.Queue.PacketQueueCount, releaseTaggedFlow)
	// 特殊处理：Duplicator的数量特意设置为PacketQueueCount，使得FlowGenerator所在环境均为单生产单消费
	for i := 0; i < cfg.Queue.PacketQueueCount; i++ {
		flowDuplicator := queue.NewDuplicator(i, 1024, flowDuplicatorQueues.Readers()[i], datatype.PseudoCloneTaggedFlowHelper)
		flowDuplicator.AddMultiQueue(flowAppQueues).AddMultiQueue(flowMarshallerQueues).Start()
	}

	// L5 - flow sender
	flowSenderQueue := manager.NewQueue(
		"5-flow-pb-to-flow-sender", cfg.Queue.FlowSenderQueueSize,
		libqueue.OptionRelease(func(p interface{}) { utils.ReleaseByteBuffer(p.(*utils.ByteBuffer)) }),
	)
	sender.NewFlowSender(
		flowMarshallerQueues.Readers(), flowSenderQueue, flowSenderQueue,
		cfg.Stream, cfg.StreamPort, cfg.Queue.FlowSenderQueueSize).Start()

	// L5 - flow app
	flowDocMarshallerQueue := manager.NewQueues(
		"5-flow-doc-to-marshaller",
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
