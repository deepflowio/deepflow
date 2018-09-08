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

	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
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

	controllers := make([]net.IP, 0, len(cfg.ControllerIps))
	for _, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		controllers = append(controllers, ip)
	}
	synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.ControllerPort)
	synchronizer.Start()

	stats.StartStatsd(net.ParseIP(cfg.StatsdServer), 10*time.Second)

	manager := queue.NewManager()

	// L1 - packet source
	filterQueue := manager.NewQueue("1-meta-packet-to-filter", 1024*64, &MetaPacket{})

	tridentAdapter := adapter.NewTridentAdapter(filterQueue)
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
		if _, err := capture.StartCapture(iface, localIp, false, filterQueue); err != nil {
			log.Error(err)
			return
		}
	}
	for _, iface := range cfg.TapInterfaces {
		if _, err := capture.StartCapture(iface, localIp, true, filterQueue); err != nil {
			log.Error(err)
			return
		}
	}

	// L2 - packet filter
	meteringAppQueue := manager.NewQueue("2-meta-packet-to-metering-app", 1024*64, &MetaPacket{})
	flowGeneratorQueue := manager.NewQueue("2-meta-packet-to-flow-generator", 1024*64, &MetaPacket{})
	labelerManager := labeler.NewLabelerManager(filterQueue)
	labelerManager.RegisterAppQueue(labeler.METERING_QUEUE, meteringAppQueue)
	labelerManager.RegisterAppQueue(labeler.FLOW_QUEUE, flowGeneratorQueue)
	labelerManager.Start()
	synchronizer.Register(func(response *trident.SyncResponse) {
		labelerManager.OnPlatformDataChange(convert2PlatformData(response))
		labelerManager.OnIpGroupDataChange(convert2IpGroupdata(response))
		labelerManager.OnPolicyDataChange(convert2AclData(response))
	})

	// L3 - flow-generator & apps
	flowGenOutput := manager.NewQueue("3-tagged-flow-to-duplicator", 1024*16, &TaggedFlow{})
	flowGenerator := flowgenerator.New(flowGeneratorQueue, flowGenOutput, 60)
	if flowGenerator == nil {
		return
	}
	flowGenerator.Start()

	flowAppQueue := manager.NewQueue("4-tagged-flow-to-flow-app", 1024*16, &TaggedFlow{})
	flowSenderQueue := manager.NewQueue("4-tagged-flow-to-stream", 1024*16, &TaggedFlow{})
	queue.NewDuplicator(1024, flowGenOutput, flowAppQueue, flowSenderQueue).Start()
	sender.NewFlowSender(flowSenderQueue, cfg.Stream.Ip, cfg.Stream.Port).Start()

	zmqFlowAppOutputQueue := manager.NewQueue("5-flow-doc-to-zero", 1024*16, &api.Document{})
	flowMapProcess := mapreduce.NewFlowMapProcess(zmqFlowAppOutputQueue)

	zmqMeteringAppOutputQueue := manager.NewQueue("4-metering-doc-to-zero", 1024*16, &api.Document{})
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
			meteringAppQueue.Put(&flushMetering)
			meteringTimer.Reset(queueFlushTime)
		}
	}()
	go func() {
		for {
			metaPacket := meteringAppQueue.Get().(*MetaPacket)
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
