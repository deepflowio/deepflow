package ext_metrics

import (
	"net"
	"strconv"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/debug"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
	libqueue "gitlab.yunshan.net/yunshan/droplet-libs/queue"
	"gitlab.yunshan.net/yunshan/droplet-libs/receiver"
	dropletqueue "gitlab.yunshan.net/yunshan/droplet/droplet/queue"
	"gitlab.yunshan.net/yunshan/droplet/dropletctl"
	"gitlab.yunshan.net/yunshan/droplet/ext_metrics/config"
	"gitlab.yunshan.net/yunshan/droplet/ext_metrics/dbwriter"
	"gitlab.yunshan.net/yunshan/droplet/ext_metrics/decoder"
	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"
)

const (
	CMD_PLATFORMDATA_EXT_METRICS = 35
)

type ExtMetrics struct {
	Config     *config.Config
	Telegraf   *Metricsor
	Prometheus *Metricsor
}

type Metricsor struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	Writer        *dbwriter.ExtMetricsWriter
}

func NewExtMetrics(config *config.Config, recv *receiver.Receiver) (*ExtMetrics, error) {
	manager := dropletqueue.NewManager(dropletctl.DROPLETCTL_EXTMETRICS_QUEUE)
	controllers := make([]net.IP, len(config.ControllerIPs))
	for i, ipString := range config.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}

	telegraf := NewMetricsor(datatype.MESSAGE_TYPE_TELEGRAF, config, controllers, manager, recv)
	prometheus := NewMetricsor(datatype.MESSAGE_TYPE_PROMETHEUS, config, controllers, manager, recv)
	return &ExtMetrics{
		Config:     config,
		Telegraf:   telegraf,
		Prometheus: prometheus,
	}, nil
}

func NewMetricsor(msgType datatype.MessageType, config *config.Config, controllers []net.IP, manager *dropletqueue.Manager, recv *receiver.Receiver) *Metricsor {
	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, config.ControllerPort, "ext-metrics-"+msgType.String()+"-"+strconv.Itoa(i), "", nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA_EXT_METRICS, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			dbwriter.NewExtMetricsWriter(config),
		)
	}
	return &Metricsor{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}
}

func (m *Metricsor) Start() {
	for _, platformData := range m.PlatformDatas {
		platformData.Start()
	}

	for _, decoder := range m.Decoders {
		go decoder.Run()
	}
}

func (m *Metricsor) Close() {
	for _, platformData := range m.PlatformDatas {
		platformData.Close()
	}
}

func (s *ExtMetrics) Start() {
	s.Telegraf.Start()
	s.Prometheus.Start()
}

func (s *ExtMetrics) Close() {
	s.Telegraf.Close()
	s.Prometheus.Close()
}
