package droplet

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"

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

	manager := queue.NewManager()

	filterQueue := manager.NewQueue("ToFilter", 1000, &MetaPacket{})
	tridentAdapter := adapter.NewTridentAdapter(filterQueue)
	if tridentAdapter == nil {
		return
	}

	flowQueue := manager.NewQueue("FilterToFlow", 1000, &MetaPacket{})
	meteringQueue := manager.NewQueue("FilterToMetering", 1000, &MetaPacket{})
	labelerManager := labeler.NewLabelerManager(filterQueue)
	labelerManager.RegisterAppQueue(labeler.METERING_QUEUE, meteringQueue)
	labelerManager.RegisterAppQueue(labeler.FLOW_QUEUE, flowQueue)
	labelerManager.Start()
	synchronizer.Register(func(response *trident.SyncResponse) {
		labelerManager.OnPlatformDataChange(convert2PlatformData(response))
		labelerManager.OnIpGroupDataChange(convert2IpGroupdata(response))
	})

	flowAppOutputQueue := manager.NewQueue("flowAppOutputQueue", 1000, &TaggedFlow{})
	flowGenerator := flowgenerator.New(flowQueue, flowAppOutputQueue, 60)
	if flowGenerator == nil {
		return
	}

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

	flowGenerator.Start()
	tridentAdapter.Start(true)

	stats.StartStatsd(net.ParseIP(cfg.StatsdServer))

	flowMapProcess := mapreduce.NewFlowMapProcess()
	meteringProcess := mapreduce.NewMeteringMapProcess()
	go func() {
		for {
			taggedFlow := flowAppOutputQueue.Get().(*TaggedFlow)
			log.Info(taggedFlow)
			flowMapProcess.Process(*taggedFlow)
		}
	}()
	go func() {
		for {
			metaPacket := meteringQueue.Get().(*MetaPacket)
			meteringProcess.Process(*metaPacket)
		}
	}()
}
