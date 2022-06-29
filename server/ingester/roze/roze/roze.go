package roze

import (
	"net"
	_ "net/http/pprof"
	"strconv"
	"time"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/ingester/droplet/queue"
	"github.com/metaflowys/metaflow/server/ingester/dropletctl"
	"github.com/metaflowys/metaflow/server/ingester/roze/config"
	"github.com/metaflowys/metaflow/server/ingester/roze/dbwriter"
	"github.com/metaflowys/metaflow/server/ingester/roze/unmarshaller"
	"github.com/metaflowys/metaflow/server/libs/datatype"
	"github.com/metaflowys/metaflow/server/libs/debug"
	"github.com/metaflowys/metaflow/server/libs/grpc"
	libqueue "github.com/metaflowys/metaflow/server/libs/queue"
	"github.com/metaflowys/metaflow/server/libs/receiver"
)

const (
	CMD_PLATFORMDATA = 33
)

var log = logging.MustGetLogger("roze")

type Roze struct {
	unmarshallers []*unmarshaller.Unmarshaller
	platformDatas []*grpc.PlatformInfoTable
	dbwriter      *dbwriter.DbWriter
}

func NewRoze(cfg *config.Config, recv *receiver.Receiver) (*Roze, error) {
	roze := Roze{}

	controllers := make([]net.IP, len(cfg.Base.ControllerIPs))
	for i, ipString := range cfg.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}

	manager := queue.NewManager(dropletctl.DROPLETCTL_ROZE_QUEUE)
	unmarshallQueueCount := int(cfg.UnmarshallQueueCount)
	unmarshallQueues := manager.NewQueuesUnmarshal(
		"1-recv-unmarshall", int(cfg.UnmarshallQueueSize), unmarshallQueueCount, 1,
		unmarshaller.DecodeForQueueMonitor,
		libqueue.OptionFlushIndicator(unmarshaller.FLUSH_INTERVAL*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(datatype.MESSAGE_TYPE_METRICS, unmarshallQueues, unmarshallQueueCount)

	var err error
	roze.dbwriter, err = dbwriter.NewDbWriter(cfg.Base.CKDB.Primary, cfg.Base.CKDB.Secondary, cfg.Base.CKDBAuth.Username, cfg.Base.CKDBAuth.Password, cfg.ReplicaEnabled, cfg.CKWriterConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	roze.platformDatas = make([]*grpc.PlatformInfoTable, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		if i == 0 {
			// 只第一个上报数据节点信息
			roze.platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(cfg.Base.ControllerPort), "roze", cfg.Pcap.FileDirectory, cfg.Base.NodeIP, recv)
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, roze.platformDatas[i])
		} else {
			roze.platformDatas[i] = grpc.NewPlatformInfoTable(controllers, int(cfg.Base.ControllerPort), "roze-"+strconv.Itoa(i), "", cfg.Base.NodeIP, nil)
		}
		roze.unmarshallers[i] = unmarshaller.NewUnmarshaller(i, roze.platformDatas[i], cfg.DisableSecondWrite, libqueue.QueueReader(unmarshallQueues.FixedMultiQueue[i]), roze.dbwriter)
	}

	return &roze, nil
}

func (r *Roze) Start() {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].Start()
		go r.unmarshallers[i].QueueProcess()
	}
}

func (r *Roze) Close() {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].Close()
	}
	r.dbwriter.Close()
}
