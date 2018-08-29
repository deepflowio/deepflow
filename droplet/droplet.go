package droplet

import (
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
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/flowgenerator"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/mapreduce"
	"gitlab.x.lan/yunshan/droplet/packet"
	"gitlab.x.lan/yunshan/droplet/queue"
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

func Start(configPath string) {
	cfg := config.Load(configPath)
	InitLog(cfg.LogFile, cfg.LogLevel)

	if cfg.Profiler {
		startProfiler()
	}

	ips := make([]net.IP, 0, len(cfg.ControllerIps))
	for _, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		ips = append(ips, ip)
	}
	synchronizer := config.NewRpcConfigSynchronizer(ips, cfg.ControllerPort)
	synchronizer.Start()

	stats.StartStatsd(net.ParseIP(cfg.StatsdServer), 10*time.Second)

	manager := queue.NewManager()

	// L1 - packet source
	filterQueue := manager.NewQueue("1-meta-packet-to-filter", 1000, &MetaPacket{})

	tridentAdapter := adapter.NewTridentAdapter(filterQueue)
	if tridentAdapter == nil {
		return
	}
	tridentAdapter.Start()

	for _, iface := range cfg.DataInterfaces {
		capture, err := packet.NewCapture(iface, ips[0], false, filterQueue)
		if err != nil {
			log.Error(err)
			return
		}
		capture.Start()
	}
	for _, iface := range cfg.TapInterfaces {
		capture, err := packet.NewCapture(iface, ips[0], true, filterQueue)
		if err != nil {
			log.Error(err)
			return
		}
		capture.Start()
	}

	// L2 - packet filter
	meteringAppQueue := manager.NewQueue("2-meta-packet-to-metering-app", 1000, &MetaPacket{})
	flowGeneratorQueue := manager.NewQueue("2-meta-packet-to-flow-generator", 1000, &MetaPacket{})
	labelerManager := labeler.NewLabelerManager(filterQueue)
	labelerManager.RegisterAppQueue(labeler.METERING_QUEUE, meteringAppQueue)
	labelerManager.RegisterAppQueue(labeler.FLOW_QUEUE, flowGeneratorQueue)
	labelerManager.Start()
	synchronizer.Register(func(response *trident.SyncResponse) {
		labelerManager.OnPlatformDataChange(convert2PlatformData(response))
		labelerManager.OnIpGroupDataChange(convert2IpGroupdata(response))
	})

	// L3 - flow-generator & apps
	flowAppQueue := manager.NewQueue("3-tagged-flow-to-flow-app", 1000, &TaggedFlow{})
	flowGenerator := flowgenerator.New(flowGeneratorQueue, flowAppQueue, 60)
	if flowGenerator == nil {
		return
	}
	flowGenerator.Start()

	flowMapProcess := mapreduce.NewFlowMapProcess()
	meteringProcess := mapreduce.NewMeteringMapProcess()
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
			log.Info(taggedFlow)
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
}
