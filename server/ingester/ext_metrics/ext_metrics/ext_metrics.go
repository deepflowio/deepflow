package ext_metrics

import (
	"net"
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/metaflowys/metaflow/server/ingester/droplet/queue"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/config"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/dbwriter"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/decoder"
	"github.com/metaflowys/metaflow/server/ingester/ingesterctl"
	"github.com/metaflowys/metaflow/server/libs/datatype"
	"github.com/metaflowys/metaflow/server/libs/debug"
	"github.com/metaflowys/metaflow/server/libs/grpc"
	"github.com/metaflowys/metaflow/server/libs/queue"
	libqueue "github.com/metaflowys/metaflow/server/libs/queue"
	"github.com/metaflowys/metaflow/server/libs/receiver"
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
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EXTMETRICS_QUEUE)
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
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

	metricsWriter := dbwriter.NewExtMetricsWriter(msgType, config)
	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(config.Base.ControllerPort), "ext-metrics-"+msgType.String()+"-"+strconv.Itoa(i), "", config.Base.NodeIP, nil)
		if i == 0 {
			debug.ServerRegisterSimple(CMD_PLATFORMDATA_EXT_METRICS, platformDatas[i])
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			metricsWriter,
			config,
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

func (s *ExtMetrics) Close() error {
	s.Telegraf.Close()
	s.Prometheus.Close()
	return nil
}
