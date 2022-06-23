package roze

import (
	"net"
	_ "net/http/pprof"
	"strconv"
	"time"

	logging "github.com/op/go-logging"
	"server/libs/datatype"
	"server/libs/debug"
	"server/libs/grpc"
	libqueue "server/libs/queue"
	"server/libs/receiver"

	"github.com/yunshan/droplet/droplet/queue"
	"github.com/yunshan/droplet/dropletctl"
	"github.com/yunshan/droplet/roze/config"
	"github.com/yunshan/droplet/roze/dbwriter"
	"github.com/yunshan/droplet/roze/unmarshaller"
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

	controllers := make([]net.IP, len(cfg.ControllerIPs))
	for i, ipString := range cfg.ControllerIPs {
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
	roze.dbwriter, err = dbwriter.NewDbWriter(cfg.CKDB.Primary, cfg.CKDB.Secondary, cfg.CKDBAuth.Username, cfg.CKDBAuth.Password, cfg.ReplicaEnabled, cfg.CKWriterConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	roze.platformDatas = make([]*grpc.PlatformInfoTable, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		if i == 0 {
			// 只第一个上报数据节点信息
			roze.platformDatas[i] = grpc.NewPlatformInfoTable(controllers, cfg.ControllerPort, "roze", cfg.Pcap.FileDirectory, recv)
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, roze.platformDatas[i])
		} else {
			roze.platformDatas[i] = grpc.NewPlatformInfoTable(controllers, cfg.ControllerPort, "roze-"+strconv.Itoa(i), "", nil)
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
