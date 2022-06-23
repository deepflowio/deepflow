package droplet

import (
	"io"
	"net"
	_ "net/http/pprof"
	"time"

	logging "github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	libpcap "gitlab.yunshan.net/yunshan/droplet-libs/pcap"
	libqueue "gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/receiver"

	"gitlab.yunshan.net/yunshan/droplet/droplet/adapter"
	"gitlab.yunshan.net/yunshan/droplet/droplet/config"
	"gitlab.yunshan.net/yunshan/droplet/droplet/labeler"
	"gitlab.yunshan.net/yunshan/droplet/droplet/pcap"
	"gitlab.yunshan.net/yunshan/droplet/droplet/queue"
	"gitlab.yunshan.net/yunshan/droplet/droplet/statsd"
	"gitlab.yunshan.net/yunshan/droplet/droplet/syslog"
	"gitlab.yunshan.net/yunshan/droplet/dropletctl"
	"gitlab.yunshan.net/yunshan/message/trident"
)

var log = logging.MustGetLogger("droplet")

func Start(cfg *config.Config, recv *receiver.Receiver) (closers []io.Closer) {

	controllers := make([]net.IP, len(cfg.ControllerIps))
	for i, ipString := range cfg.ControllerIps {
		ip := net.ParseIP(ipString)
		if ipv4 := ip.To4(); ipv4 == nil {
			controllers[i] = ip
		} else {
			controllers[i] = ipv4
		}
	}

	cleaner := libpcap.NewCleaner(5*time.Minute, int64(cfg.PCap.MaxDirectorySizeGB)<<30, int64(cfg.PCap.DiskFreeSpaceMarginGB)<<30, cfg.PCap.FileDirectory)
	cleaner.Start()

	// L1 - packet source from tridentAdapter
	manager := queue.NewManager(dropletctl.DROPLETCTL_QUEUE)

	statsdRecvQueues := manager.NewQueues(
		"1-receiver-to-statsd", cfg.Queue.StatsdQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)
	syslogRecvQueues := manager.NewQueues(
		"1-receiver-to-syslog", cfg.Queue.SyslogQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)
	compressedPacketRecvQueues := manager.NewQueues(
		"1-receiver-to-meta-packet", cfg.Queue.CompressedQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)

	recv.RegistHandler(datatype.MESSAGE_TYPE_SYSLOG, syslogRecvQueues, 1)
	recv.RegistHandler(datatype.MESSAGE_TYPE_STATSD, statsdRecvQueues, 1)
	recv.RegistHandler(datatype.MESSAGE_TYPE_COMPRESS, compressedPacketRecvQueues, 1)

	syslog.NewSyslogWriter(syslogRecvQueues.Readers()[0], cfg.SyslogDirectory, cfg.ESSyslog, cfg.ESHostPorts, cfg.ESAuth.User, cfg.ESAuth.Password)
	statsd.NewStatsdWriter(statsdRecvQueues.Readers()[0])

	releaseMetaPacketBlock := func(x interface{}) {
		datatype.ReleaseMetaPacketBlock(x.(*datatype.MetaPacketBlock))
	}
	labelerQueues := manager.NewQueues(
		"2-meta-packet-block-to-labeler", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionRelease(releaseMetaPacketBlock),
	)
	tridentAdapter := adapter.NewTridentAdapter(compressedPacketRecvQueues.Readers()[0], labelerQueues.Writers(), cfg.Adapter.OrderingCacheSize)
	if tridentAdapter == nil {
		return
	}

	pcapAppQueues := manager.NewQueues(
		"3-meta-packet-block-to-pcap-app", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second*10), libqueue.OptionRelease(releaseMetaPacketBlock),
	)

	// labeler
	labelerManager := labeler.NewLabelerManager(labelerQueues.Readers(), pcapAppQueues.Writers(),
		cfg.Queue.PacketQueueCount, cfg.Labeler.Level, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable)
	labelerManager.Start()

	if len(controllers) > 0 {
		synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.ControllerPort, cfg.RpcTimeout)
		synchronizer.Register(func(response *trident.SyncResponse, version *config.RpcInfoVersions) {
			log.Debug(response, version)
			cleaner.UpdatePcapDataRetention(time.Duration(response.Config.GetPcapDataRetention()) * time.Hour * 24)
			// Labeler更新策略信息
			labelerManager.OnAclDataChange(response)
		})
		synchronizer.Start()
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
		cfg.PCap.FileDirectory,
	).Start()
	closers = append(closers, pcapClosers...)
	// 其他所有组件启动完成以后运行TridentAdapter，尽量避免启动过程中队列丢包
	tridentAdapter.Start()
	return
}
