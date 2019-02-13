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
	"gitlab.x.lan/yunshan/droplet/capture"
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
	// L1 - packet source
	manager := queue.NewManager()
	packetSourceCount := 1 + len(cfg.TapInterfaces) // tridentAdapter and capture
	releaseMetaPacket := func(x interface{}) {
		datatype.ReleaseMetaPacket(x.(*datatype.MetaPacket))
	}
	labelerQueues := manager.NewQueues(
		"1-meta-packet-to-labeler", cfg.Queue.LabelerQueueSize, cfg.Queue.LabelerQueueCount, packetSourceCount,
		releaseMetaPacket,
	)

	tridentAdapter := adapter.NewTridentAdapter(labelerQueues, cfg.Adapter.SocketBufferSize, cfg.Adapter.OrderingCacheSize, cfg.Adapter.TimeDiffAdjust)
	if tridentAdapter == nil {
		return
	}
	tridentAdapter.Start()

	localIp, err := getLocalIp()
	if err != nil {
		log.Error(err)
		return
	} else if localIp.String() == "127.0.0.1" {
		log.Error("Invalid ip resolved by hostname")
		os.Exit(1)
	}
	remoteSegmentSet := capture.NewSegmentSet()

	launcher := capture.CaptureLauncher{
		Ip:             localIp,
		RemoteSegments: remoteSegmentSet,
		DefaultTapType: cfg.DefaultTapType,
		OutputQueue:    labelerQueues,
	}
	for tapId, iface := range cfg.TapInterfaces {
		closer, err := launcher.StartWith(tapId, iface)
		if err != nil {
			log.Error(err)
			return
		}
		closers = append(closers, closer)
	}

	// L2 - packet labeler
	flowGeneratorQueues := manager.NewQueues(
		"2-meta-packet-to-flow-generator", cfg.Queue.FlowGeneratorQueueSize, cfg.Queue.FlowGeneratorQueueCount, cfg.Queue.LabelerQueueCount,
		releaseMetaPacket,
	)
	meteringAppQueues := manager.NewQueues(
		"2-meta-packet-to-metering-app", cfg.Queue.MeteringAppQueueSize, cfg.Queue.MeteringAppQueueCount, cfg.Queue.LabelerQueueCount,
		libqueue.OptionFlushIndicator(time.Minute), releaseMetaPacket,
	)
	pcapAppQueues := manager.NewQueues(
		"2-meta-packet-to-pcap-app", cfg.Queue.PCapAppQueueSize, cfg.Queue.PCapAppQueueCount, cfg.Queue.LabelerQueueCount,
		libqueue.OptionFlushIndicator(time.Minute), releaseMetaPacket,
	)

	labelerManager := labeler.NewLabelerManager(labelerQueues, cfg.Queue.LabelerQueueCount, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_FLOW, flowGeneratorQueues)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_METERING, meteringAppQueues)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_PCAP, pcapAppQueues)
	synchronizer.Register(func(response *trident.SyncResponse) {
		log.Debug(response)
		// Capture更新RemoteSegments
		rpcRemoteSegments := response.GetRemoteSegments()
		remoteSegments := make([]net.HardwareAddr, 0, len(rpcRemoteSegments))
		for _, segment := range rpcRemoteSegments {
			for _, macString := range segment.GetMac() {
				mac, err := net.ParseMAC(macString)
				if err != nil {
					log.Warning("Invalid MAC ", macString)
					continue
				}
				remoteSegments = append(remoteSegments, mac)
			}
		}
		remoteSegmentSet.OnSegmentChange(remoteSegments)
		// Labeler更新策略信息
		labelerManager.OnAclDataChange(response)
	})
	labelerManager.Start()

	// L3 - flow generator & metering marshaller & pcap
	docsInBuffer := int(cfg.Queue.DocsQueueSize)
	variedDocLimit := int(cfg.MapReduce.VariedDocLimit)
	windowSize := int(cfg.MapReduce.WindowSize)
	windowMoveMargin := int(cfg.MapReduce.WindowMoveMargin)
	releaseTaggedFlow := func(x interface{}) {
		datatype.ReleaseTaggedFlow(x.(*datatype.TaggedFlow))
	}
	flowDuplicatorQueue := manager.NewQueue("3-tagged-flow-to-flow-duplicator", cfg.Queue.FlowDuplicatorQueueSize, releaseTaggedFlow)
	meteringAppOutputQueue := manager.NewQueues(
		"3-metering-doc-to-marshaller",
		cfg.Queue.MeteringAppOutputQueueSize, cfg.Queue.MeteringAppOutputQueueCount, // MapReduce发送是突发的，且ZMQ发送缓慢，queueSize设置为突发的2倍
		cfg.Queue.MeteringAppQueueCount,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
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
	bufferSize := cfg.Queue.FlowGeneratorQueueSize / cfg.Queue.FlowGeneratorQueueCount
	flowLimitNum := cfg.FlowGenerator.FlowCountLimit / int32(cfg.Queue.FlowGeneratorQueueCount)
	for i := 0; i < cfg.Queue.FlowGeneratorQueueCount; i++ {
		flowGenerator := flowgenerator.New(flowGeneratorQueues, flowDuplicatorQueue, bufferSize, flowLimitNum, i)
		flowGenerator.Start()
	}

	mapreduce.NewMeteringMapProcess(
		meteringAppOutputQueue, meteringAppQueues, cfg.Queue.MeteringAppQueueCount,
		docsInBuffer, variedDocLimit, windowSize, windowMoveMargin).Start()

	pcapClosers := pcap.NewWorkerManager(
		pcapAppQueues,
		cfg.Queue.PCapAppQueueCount,
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

	// L4 - flow duplicator & flow sender
	flowAppQueue := manager.NewQueues(
		"4-tagged-flow-to-flow-app", cfg.Queue.FlowAppQueueSize,
		cfg.Queue.FlowAppQueueCount, cfg.Queue.FlowGeneratorQueueCount, libqueue.OptionFlushIndicator(time.Minute), releaseTaggedFlow)
	flowSenderQueue := manager.NewQueue(
		"4-tagged-flow-to-stream", cfg.Queue.FlowSenderQueueSize, releaseTaggedFlow) // ZMQ发送缓慢，queueSize设置为上游的2倍

	flowDuplicator := queue.NewDuplicator(1024, flowDuplicatorQueue, datatype.PseudoCloneTaggedFlowHelper)
	flowDuplicator.AddMultiQueue(flowAppQueue, cfg.Queue.FlowAppQueueCount).AddQueue(flowSenderQueue).Start()
	sender.NewFlowSender(flowSenderQueue, cfg.Stream, cfg.StreamPort, cfg.Queue.FlowSenderQueueSize).Start()

	// L5 - flow doc marshaller
	flowAppOutputQueue := manager.NewQueues(
		"5-flow-doc-to-marshaller",
		cfg.Queue.FlowAppOutputQueueSize, cfg.Queue.FlowAppOutputQueueCount, // MapReduce发送是突发的，且ZMQ发送缓慢，queueSize设置为突发的2倍
		cfg.Queue.FlowAppQueueCount,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)
	mapreduce.NewFlowMapProcess(
		flowAppOutputQueue, flowAppQueue, cfg.Queue.FlowAppQueueCount,
		docsInBuffer, variedDocLimit, windowSize, windowMoveMargin).Start()

	// L6 - flow/metering doc sender
	builder := sender.NewZeroDocumentSenderBuilder()
	builder.AddQueue(meteringAppOutputQueue, cfg.Queue.MeteringAppOutputQueueCount)
	builder.AddQueue(flowAppOutputQueue, cfg.Queue.FlowAppOutputQueueCount)
	builder.AddListenPorts(cfg.ZeroPorts...)
	builder.Build().Start(cfg.Queue.DocSenderQueueSize) // MapReduce发送是突发的，且ZMQ发送缓慢，queueSize设置为突发的2倍
	return
}
