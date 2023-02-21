package dbwriter

import (
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/ingester/profile/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/utils"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("profile.dbwriter")

const (
	PROFILE_DB    = "profile"
	PROFILE_TABLE = "in_process"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	MetricsCount int64 `statsd:"metrics-count"`
	WriteErr     int64 `statsd:"write-err"`
}

type ProfileWriter struct {
	msgType           datatype.MessageType
	ckdbAddrs         []string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ttl               int
	writerConfig      baseconfig.CKWriterConfig
	ckdbWatcher       *baseconfig.Watcher
	ckWriter          *ckwriter.CKWriter

	counter *Counter
	utils.Closable
}

func (p *ProfileWriter) Write(m interface{}) {
	p.ckWriter.Put(m)
}

func NewProfileWriter(msgType datatype.MessageType, config *config.Config) (*ProfileWriter, error) {
	writer := &ProfileWriter{
		msgType:           msgType,
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.ProfileTTL,
		ckdbWatcher:       config.Base.CKDB.Watcher,
		writerConfig:      config.CKWriterConfig,
	}
	table := GenProfileCKTable(writer.ckdbCluster, PROFILE_DB, PROFILE_TABLE, writer.ckdbStoragePolicy, writer.ttl, ckdb.GetColdStorage(writer.ckdbColdStorages, PROFILE_DB, PROFILE_TABLE))
	ckwriter, err := ckwriter.NewCKWriter(
		writer.ckdbAddrs, writer.ckdbUsername, writer.ckdbPassword,
		PROFILE_TABLE, table,
		writer.writerConfig.QueueCount, writer.writerConfig.QueueSize,
		writer.writerConfig.BatchSize, writer.writerConfig.FlushTimeout)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	writer.ckWriter = ckwriter
	writer.ckWriter.Run()
	return writer, nil
}
