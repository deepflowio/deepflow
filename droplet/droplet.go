package droplet

import (
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
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
	stats.SetRemote(net.ParseIP(cfg.StatsdServer))

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
	for _, iface := range cfg.TapInterfaces {
		if _, err := capture.StartCapture(iface, localIp, labelerQueues); err != nil {
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
	meteringAppQueues := manager.NewQueues("2-meta-packet-to-metering-app", queueSize, meteringAppQueueCount, labelerQueueCount)

	labelerManager := labeler.NewLabelerManager(labelerQueues, labelerQueueCount, cfg.Labeler.MapSizeLimit)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_FLOW, flowGeneratorQueues)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_METERING, meteringAppQueues)
	labelerManager.Start()

	synchronizer.Register(func(response *trident.SyncResponse) {
		log.Debug(response)
		labelerManager.OnAclDataChange(response)
	})

	// L3 - flow generator & metering map
	flowDuplicatorQueue := manager.NewQueue("3-tagged-flow-to-flow-duplicator", queueSize>>2)
	meteringAppOutputQueue := manager.NewQueue("3-metering-doc-to-zero", queueSize>>2)

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

	meteringMapProcess := mapreduce.NewMeteringMapProcess(meteringAppOutputQueue, meteringAppQueues, meteringAppQueueCount)
	meteringMapProcess.Start()

	// L4 - flow duplicator & flow sender
	flowAppQueue := manager.NewQueue("4-tagged-flow-to-flow-app", queueSize>>2)
	flowSenderQueue := manager.NewQueue("4-tagged-flow-to-stream", queueSize>>2)

	queue.NewDuplicator(1024, flowDuplicatorQueue, flowAppQueue, flowSenderQueue).Start()
	sender.NewFlowSender(flowSenderQueue, cfg.Stream.Ip, cfg.Stream.Port).Start()

	// L5 - flow map
	flowAppOutputQueue := manager.NewQueue("5-flow-doc-to-zero", queueSize>>2)
	flowMapProcess := mapreduce.NewFlowMapProcess(flowAppOutputQueue)

	queueFlushTime := time.Minute
	flowTimer := time.NewTimer(queueFlushTime)
	go func() {
		for {
			<-flowTimer.C
			flushFlow := TaggedFlow{Flow: Flow{StartTime: 0}}
			flowAppQueue.Put(&flushFlow)
			flowTimer.Reset(queueFlushTime)
		}
	}()
	go func() {
		for {
			taggedFlow := flowAppQueue.Get().(*TaggedFlow)
			if taggedFlow.StartTime > 0 {
				flowMapProcess.Process(*taggedFlow)
			} else if flowMapProcess.NeedFlush() {
				flowMapProcess.Flush()
			}
		}
	}()

	builder := sender.NewZeroDocumentSenderBuilder()
	builder.AddQueue(flowAppOutputQueue, meteringAppOutputQueue)
	for _, zero := range cfg.Zeroes {
		builder.AddZero(zero.Ip, zero.Port)
	}
	builder.Build().Start()
}
