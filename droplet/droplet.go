package droplet

import (
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
	libqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/capture"
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/flowgenerator"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/mapreduce"
	"gitlab.x.lan/yunshan/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/sender"
	"gitlab.x.lan/yunshan/message/trident"
)

var log = logging.MustGetLogger("droplet")

func startProfiler() {
	go func() {
		if err := http.ListenAndServe("0.0.0.0:8000", nil); err != nil {
			log.Error("Start pprof on http 0.0.0.0:8000 failed")
			os.Exit(1)
		}
	}()
}

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

func Start(configPath string) {
	cfg := config.Load(configPath)
	InitLog(cfg.LogFile, cfg.LogLevel)

	if cfg.Profiler {
		startProfiler()
	}

	stats.SetMinInterval(10 * time.Second)

	controllers := make([]net.IP, 0, len(cfg.ControllerIps))
	for _, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		controllers = append(controllers, ip)
	}
	synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.ControllerPort)
	synchronizer.Start()

	// L1 - packet source
	manager := queue.NewManager()
	queueSize := int(cfg.Queue.QueueSize)
	labelerQueueCount := int(cfg.Queue.LabelerQueueCount)
	packetSourceCount := 1 // Only adapter will use MultiQueue.Puts
	labelerQueues := manager.NewQueues("1-meta-packet-to-labeler", queueSize, labelerQueueCount, packetSourceCount)

	localIp, err := getLocalIp()
	if err != nil {
		log.Error(err)
		return
	}
	remoteSegmentSet := capture.NewSegmentSet()

	launcher := capture.CaptureLauncher{localIp, remoteSegmentSet, labelerQueues}
	for _, iface := range cfg.TapInterfaces {
		if _, err := launcher.StartWith(iface); err != nil {
			log.Error(err)
			return
		}
	}

	tridentAdapter := adapter.NewTridentAdapter(labelerQueues)
	if tridentAdapter == nil {
		return
	}
	tridentAdapter.Start()

	// L2 - packet labeler
	flowGeneratorQueueCount := int(cfg.Queue.FlowGeneratorQueueCount)
	meteringAppQueueCount := int(cfg.Queue.MeteringAppQueueCount)
	flowGeneratorQueues := manager.NewQueues("2-meta-packet-to-flow-generator", queueSize, flowGeneratorQueueCount, labelerQueueCount)
	meteringAppQueues := manager.NewQueues(
		"2-meta-packet-to-metering-app", queueSize, meteringAppQueueCount, labelerQueueCount,
		libqueue.OptionFlushIndicator(time.Minute),
	)

	labelerManager := labeler.NewLabelerManager(labelerQueues, labelerQueueCount, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_FLOW, flowGeneratorQueues)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_METERING, meteringAppQueues)
	synchronizer.Register(func(response *trident.SyncResponse) {
		log.Debug(response)
		// Capture更新RemoteSegments
		rpcRemoteSegments := response.GetRemoteSegments()
		remoteSegments := make([]net.HardwareAddr, 0, len(rpcRemoteSegments))
		for _, segment := range rpcRemoteSegments {
			for _, macString := range segment.GetMac() {
				mac, err := net.ParseMAC(macString)
				if err != nil {
					log.Warning("Invalid mac ", macString)
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

	// L3 - flow generator & metering marshaller
	docsInBuffer := int(cfg.MapReduce.DocsInBuffer)
	windowSize := int(cfg.MapReduce.WindowSize)
	flowDuplicatorQueue := manager.NewQueue("3-tagged-flow-to-flow-duplicator", queueSize>>2)
	meteringAppOutputQueue := manager.NewQueue(
		"3-metering-doc-to-marshaller", docsInBuffer<<1,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)

	timeoutConfig := flowgenerator.TimeoutConfig{
		Opening:         cfg.FlowGenerator.OthersTimeout,
		Established:     cfg.FlowGenerator.EstablishedTimeout,
		Closing:         cfg.FlowGenerator.OthersTimeout,
		EstablishedRst:  cfg.FlowGenerator.ClosingRstTimeout,
		Exception:       cfg.FlowGenerator.OthersTimeout,
		ClosedFin:       0,
		SingleDirection: cfg.FlowGenerator.OthersTimeout,
	}
	flowGeneratorConfig := flowgenerator.FlowGeneratorConfig{
		ForceReportInterval: cfg.FlowGenerator.ForceReportInterval,
		BufferSize:          queueSize / flowGeneratorQueueCount,
		FlowLimitNum:        cfg.FlowGenerator.FlowCountLimit / uint32(flowGeneratorQueueCount),
	}
	for i := 0; i < flowGeneratorQueueCount; i++ {
		flowGenerator := flowgenerator.New(flowGeneratorQueues, flowDuplicatorQueue, flowGeneratorConfig, i)
		if flowGenerator == nil {
			return
		}
		flowGenerator.SetTimeout(timeoutConfig)
		flowGenerator.Start()
	}

	mapreduce.NewMeteringMapProcess(meteringAppOutputQueue, meteringAppQueues, meteringAppQueueCount, docsInBuffer, windowSize).Start()

	// L4 - flow duplicator & flow sender
	flowAppQueueCount := int(cfg.Queue.FlowAppQueueCount)
	flowAppQueue := manager.NewQueues("4-tagged-flow-to-flow-app", queueSize>>2, flowAppQueueCount, 1, libqueue.OptionFlushIndicator(time.Minute))
	flowSenderQueue := manager.NewQueue("4-tagged-flow-to-stream", queueSize>>2)

	queue.NewDuplicator(1024, flowDuplicatorQueue).AddMultiQueue(flowAppQueue, flowAppQueueCount).AddQueue(flowSenderQueue).Start()
	sender.NewFlowSender(flowSenderQueue, cfg.Stream, cfg.StreamPort, queueSize>>2).Start()

	// L5 - flow doc marshaller
	flowAppOutputQueue := manager.NewQueue(
		"5-flow-doc-to-marshaller", docsInBuffer<<1,
		libqueue.OptionRelease(func(p interface{}) { app.ReleaseDocument(p.(*app.Document)) }),
	)
	mapreduce.NewFlowMapProcess(flowAppOutputQueue, flowAppQueue, flowAppQueueCount, docsInBuffer, windowSize).Start()

	// L6 - flow/metering doc sender
	builder := sender.NewZeroDocumentSenderBuilder()
	builder.AddQueue(flowAppOutputQueue, meteringAppOutputQueue)
	for _, zero := range cfg.ZeroHosts {
		builder.AddZero(zero, cfg.ZeroPort)
	}
	builder.Build().Start(queueSize) // MapReduce发送是突发的，且ZMQ发送缓慢，因此需要大Buffer
}
