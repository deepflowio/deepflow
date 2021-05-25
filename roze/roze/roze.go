package roze

import (
	"net"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	logging "github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	libqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/store"

	// "gitlab.x.lan/yunshan/droplet/common/datasource"
	"gitlab.x.lan/yunshan/droplet/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/roze/config"
	"gitlab.x.lan/yunshan/droplet/roze/dbwriter"
	"gitlab.x.lan/yunshan/droplet/roze/platformdata"
	"gitlab.x.lan/yunshan/droplet/roze/unmarshaller"
)

const (
	INFLUXDB_RP_1M = "rp_1m"
	INFLUXDB_RP_1S = "rp_1s"
)

var log = logging.MustGetLogger("roze")

type Roze struct {
	unmarshallers    []*unmarshaller.Unmarshaller
	InfluxdbWriter   *store.InfluxdbWriter
	InfluxdbWriterS1 *store.InfluxdbWriter
	Repair           *store.Repair
	RepairS1         *store.Repair
	dbwriter         *dbwriter.DbWriter
}

// http://x.x.x.x:20044  http://[x:x:x:x]:20044
func parseTsdbIP(httpURL string) string {
	headIndex, tailIndex := strings.Index(httpURL, "http://"), strings.Index(httpURL, ":20044")
	if tailIndex > headIndex && headIndex > -1 {
		// ipv6
		leftBracket, rightBracket := strings.Index(httpURL, "["), strings.Index(httpURL, "]")
		if rightBracket > leftBracket && leftBracket > -1 {
			return httpURL[leftBracket+1 : rightBracket]
		}
		// ipv4
		return httpURL[headIndex+len("http://") : tailIndex]
	}
	return ""
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

	platformdata.New(controllers, cfg.ControllerPort, "roze", uint32(cfg.ShardID), parseTsdbIP(cfg.TSDB.Replica), cfg.TSDBDataPath, cfg.Pcap.FileDirectory, recv)

	var err error
	roze.InfluxdbWriter, err = store.NewInfluxdbWriter(cfg.TSDB.Primary, cfg.TSDB.Replica, cfg.TSDBAuth.Username, cfg.TSDBAuth.Password, "influxdb_writer", strconv.Itoa(cfg.ShardID), cfg.StoreQueueCount, cfg.StoreQueueSize)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	roze.InfluxdbWriter.SetBatchSize(cfg.StoreBatchBufferSize)
	roze.InfluxdbWriter.SetRetentionPolicy(INFLUXDB_RP_1M, cfg.Retention.Duration, cfg.Retention.ShardDuration, true)

	if cfg.DisableSecondWriteReplica {
		roze.InfluxdbWriterS1, err = store.NewInfluxdbWriter(cfg.TSDB.Primary, "", cfg.TSDBAuth.Username, cfg.TSDBAuth.Password, "influxdb_writer_1s", strconv.Itoa(cfg.ShardID), cfg.StoreQueueCount, cfg.StoreQueueSize)
	} else {
		roze.InfluxdbWriterS1, err = store.NewInfluxdbWriter(cfg.TSDB.Primary, cfg.TSDB.Replica, cfg.TSDBAuth.Username, cfg.TSDBAuth.Password, "influxdb_writer_1s", strconv.Itoa(cfg.ShardID), cfg.StoreQueueCount, cfg.StoreQueueSize)
	}
	if err != nil {
		log.Error(err)
		return nil, err
	}
	roze.InfluxdbWriterS1.SetBatchSize(cfg.StoreBatchBufferSize)
	roze.InfluxdbWriterS1.SetRetentionPolicy(INFLUXDB_RP_1S, cfg.Retention.DurationS1, cfg.Retention.ShardDurationS1, false)

	roze.Repair, err = store.NewRepair(cfg.TSDB.Primary, cfg.TSDB.Replica, cfg.TSDBAuth.Username, cfg.TSDBAuth.Password, INFLUXDB_RP_1M, strconv.Itoa(cfg.ShardID), "^vtap_", cfg.RepairEnabled, cfg.RepairSyncDelay, cfg.RepairInterval, cfg.RepairSyncCountOnce)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.RepairS1, err = store.NewRepair(cfg.TSDB.Primary, cfg.TSDB.Replica, cfg.TSDBAuth.Username, cfg.TSDBAuth.Password, INFLUXDB_RP_1S, strconv.Itoa(cfg.ShardID), "^vtap_", cfg.RepairEnabled, cfg.RepairSyncDelay, cfg.RepairInterval, cfg.RepairSyncCountOnce*2)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.dbwriter, err = dbwriter.NewDbWriter(cfg.CKDB.Primary, cfg.CKDB.Secondary, cfg.CKDBAuth.Username, cfg.CKDBAuth.Password, cfg.ReplicaEnabled, cfg.CKWriterConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		roze.unmarshallers[i] = unmarshaller.NewUnmarshaller(i, cfg.DisableSecondWrite, cfg.DisableVtapPacket, libqueue.QueueReader(unmarshallQueues.FixedMultiQueue[i]), roze.InfluxdbWriter, roze.InfluxdbWriterS1, roze.dbwriter, cfg.StoreQueueCount)
	}

	return &roze, nil
}

func (r *Roze) Start() {
	platformdata.Start()

	unmarshallQueueCount := len(r.unmarshallers)
	for i := 0; i < unmarshallQueueCount; i++ {
		go r.unmarshallers[i].QueueProcess()
	}

	r.InfluxdbWriter.Run()
	r.InfluxdbWriterS1.Run()
	r.Repair.Run()
	r.RepairS1.Run()
}

func (r *Roze) Close() error {
	platformdata.Close()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		r.InfluxdbWriter.Close()
		wg.Done()
	}()
	wg.Wait()
	return nil
}
