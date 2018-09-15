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
	queueSize := int(cfg.QueueSize)
	filterQueueCount := int(cfg.AdapterQueueCount) + len(cfg.DataInterfaces) + len(cfg.TapInterfaces)
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

	manager := queue.NewManager()

	// L1 - packet source
	filterQueues := manager.NewQueues("1-meta-packet-to-filter", queueSize, filterQueueCount)
	tridentAdapter := adapter.NewTridentAdapter(filterQueues, filterQueueCount)
	if tridentAdapter == nil {
		return
	}
	tridentAdapter.Start()

	localIp, err := getLocalIp()
	if err != nil {
		log.Error(err)
		return
	}
	for _, iface := range cfg.DataInterfaces {
		if _, err := capture.StartCapture(iface, localIp, false, filterQueues); err != nil {
			log.Error(err)
			return
		}
	}
	for _, iface := range cfg.TapInterfaces {
		if _, err := capture.StartCapture(iface, localIp, true, filterQueues); err != nil {
			log.Error(err)
			return
		}
	}

	// L2 - packet filter
	meteringAppQueue := manager.NewQueues("2-meta-packet-to-metering-app", queueSize, int(cfg.FlowQueueCount))
	flowGeneratorQueue := manager.NewQueues("2-meta-packet-to-flow-generator", queueSize, int(cfg.FlowQueueCount))
	labelerManager := labeler.NewLabelerManager(filterQueues, 8)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_METERING, meteringAppQueue)
	labelerManager.RegisterAppQueue(labeler.QUEUE_TYPE_FLOW, flowGeneratorQueue)
	labelerManager.Start()
	synchronizer.Register(func(response *trident.SyncResponse) {
		labelerManager.OnPlatformDataChange(convert2PlatformData(response))
		labelerManager.OnIpGroupDataChange(convert2IpGroupdata(response))
		labelerManager.OnPolicyDataChange(convert2AclData(response))
	})

	// L3 - flow-generator & apps
	flowTimeout := cfg.FlowTimeout
	timeoutConfig := flowgenerator.TimeoutConfig{
		Opening:         flowTimeout.Others,
		Established:     flowTimeout.Established,
		Closing:         flowTimeout.Others,
		EstablishedRst:  flowTimeout.ClosingRst,
		Exception:       flowTimeout.Others,
		ClosedFin:       0,
		SingleDirection: flowTimeout.Others,
	}
	flowGeneratorConfig := flowgenerator.FlowGeneratorConfig{
		ForceReportInterval: flowTimeout.ForceReportInterval,
		BufferSize:          queueSize,
		FlowLimitNum:        cfg.FlowCountLimit / uint32(cfg.FlowQueueCount),
	}
	flowGenOutput := manager.NewQueue("3-tagged-flow-to-duplicator", queueSize/4)
	for i := 0; i < int(cfg.FlowQueueCount); i++ {
		flowGenerator := flowgenerator.New(flowGeneratorQueue, flowGenOutput, flowGeneratorConfig, i)
		if flowGenerator == nil {
			return
		}
		flowGenerator.SetTimeout(timeoutConfig)
		flowGenerator.Start()
	}

	flowAppQueue := manager.NewQueue("4-tagged-flow-to-flow-app", queueSize/4)
	flowSenderQueue := manager.NewQueue("4-tagged-flow-to-stream", queueSize/4)
	queue.NewDuplicator(1024, flowGenOutput, flowAppQueue, flowSenderQueue).Start()
	sender.NewFlowSender(flowSenderQueue, cfg.Stream.Ip, cfg.Stream.Port).Start()

	zmqFlowAppOutputQueue := manager.NewQueue("5-flow-doc-to-zero", queueSize/4)
	flowMapProcess := mapreduce.NewFlowMapProcess(zmqFlowAppOutputQueue)
	zmqMeteringAppOutputQueue := manager.NewQueue("4-metering-doc-to-zero", queueSize/4)

	meteringProcess := mapreduce.NewMeteringMapProcess(zmqMeteringAppOutputQueue)
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

	meteringTimer := time.NewTimer(queueFlushTime)
	go func() {
		for {
			<-meteringTimer.C
			flushMetering := MetaPacket{Timestamp: 0}
			meteringAppQueue.Put(0, &flushMetering)
			meteringTimer.Reset(queueFlushTime)
		}
	}()
	go func() {
		for {
			metaPacket := meteringAppQueue.Get(0).(*MetaPacket)
			if metaPacket.Timestamp != 0 {
				meteringProcess.Process(*metaPacket)
			} else if meteringProcess.NeedFlush() {
				meteringProcess.Flush()
			}
		}
	}()
	builder := sender.NewZeroDocumentSenderBuilder()
	builder.AddQueue(zmqFlowAppOutputQueue, zmqMeteringAppOutputQueue)
	for _, zero := range cfg.Zeroes {
		builder.AddZero(zero.Ip, zero.Port)
	}
	builder.Build().Start()
}
