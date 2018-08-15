package droplet

import (
	"net"
	"time"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/flowgen"
	"gitlab.x.lan/yunshan/droplet/handler"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/mapreduce"
	"gitlab.x.lan/yunshan/droplet/packet"
	"gitlab.x.lan/yunshan/droplet/protobuf"
	"gitlab.x.lan/yunshan/droplet/queue"
)

var log = logging.MustGetLogger("droplet")

func Start(configPath string) {
	cfg := config.Load(configPath)
	ips := make([]net.IP, 0, len(cfg.ControllerIps))
	for _, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		ips = append(ips, ip)
	}
	synchronizer := config.NewRpcConfigSynchronizer(ips, cfg.ControllerPort, 10*time.Second)
	synchronizer.Start()

	manager := queue.NewManager()

	filterQueue := manager.NewQueue("ToFilter", 1000, &handler.MetaPacket{})
	tridentAdapter := adapter.NewTridentAdapter(filterQueue)
	if tridentAdapter == nil {
		return
	}

	flowQueue := manager.NewQueue("FilterToFlow", 1000, &handler.MetaPacket{})
	meteringQueue := manager.NewQueue("FilterToMetering", 1000, &TaggedMetering{})
	labelerManager := labeler.NewLabelerManager(filterQueue, meteringQueue, flowQueue)
	labelerManager.Start()
	synchronizer.Register(func(response *protobuf.SyncResponse) {
		labelerManager.OnPlatformDataChange(convert2PlatformData(response))
		labelerManager.OnServiceDataChange(convert2ServiceData(response))
		labelerManager.OnIpGroupDataChange(convert2IpGroupdata(response))
	})

	flowAppOutputQueue := manager.NewQueue("flowAppOutputQueue", 1000, &handler.MetaPacket{})
	flowGenerator := flowgen.New(flowQueue, flowAppOutputQueue, 60)
	if flowGenerator == nil {
		return
	}
	for _, iface := range append(cfg.DataInterfaces, cfg.TapInterfaces...) {
		capture, err := packet.NewCapture(iface, ips[0], filterQueue)
		if err != nil {
			log.Error(err)
			return
		}
		capture.Start()
	}

	flowGenerator.Start()
	tridentAdapter.Start(true)

	stats.StartStatsd()
	flowMapProcess := mapreduce.NewFlowMapProcess()
	meteringProcess := mapreduce.NewMeteringMapProcess()
	go func() {
		for {
			taggedFlow := flowAppOutputQueue.Get().(*TaggedFlow)
			log.Info(flowgen.TaggedFlowString(taggedFlow))
			flowMapProcess.Process(*taggedFlow)
		}
	}()
	go func() {
		for {
			taggedMetering := meteringQueue.Get().(*TaggedMetering)
			meteringProcess.Process(*taggedMetering)
		}
	}()
}
