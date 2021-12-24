package dbwriter

import (
	logging "github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet/pkg/ckwriter"
	"gitlab.yunshan.net/yunshan/droplet/stream/common"
	"gitlab.yunshan.net/yunshan/droplet/stream/config"
	"gitlab.yunshan.net/yunshan/droplet/stream/jsonify"
)

var log = logging.MustGetLogger("stream.dbwriter")

const (
	CACHE_SIZE = 10240
)

type FlowLogWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func newFlowLogTable(id common.FlowLogID, columns []*ckdb.Column, engine ckdb.EngineType) *ckdb.Table {
	orderKeys := []string{"l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0", "server_port"}

	return &ckdb.Table{
		ID:              uint8(id),
		Database:        common.FLOW_LOG_DB,
		LocalName:       id.String() + "_local",
		GlobalName:      id.String(),
		Columns:         columns,
		TimeKey:         id.TimeKey(),
		Engine:          engine,
		PartitionFunc:   ckdb.TimeFuncHour,
		TTL:             3,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func GetFlowLogTables(engine ckdb.EngineType) []*ckdb.Table {
	return []*ckdb.Table{
		newFlowLogTable(common.L4_FLOW_ID, jsonify.FlowLoggerColumns(), engine),
		newFlowLogTable(common.L7_HTTP_ID, jsonify.HTTPLoggerColumns(), engine),
		newFlowLogTable(common.L7_DNS_ID, jsonify.DNSLoggerColumns(), engine),
		newFlowLogTable(common.L7_SQL_ID, jsonify.SQLLoggerColumns(), engine),
		newFlowLogTable(common.L7_NOSQL_ID, jsonify.NoSQLLoggerColumns(), engine),
		newFlowLogTable(common.L7_RPC_ID, jsonify.RPCLoggerColumns(), engine),
		newFlowLogTable(common.L7_MQ_ID, jsonify.MQLoggerColumns(), engine),
	}
}

func NewFlowLogWriter(primaryAddr, secondaryAddr, user, password string, replicaEnabled bool, ckWriterCfg config.CKWriterConfig) (*FlowLogWriter, error) {
	ckwriters := make([]*ckwriter.CKWriter, common.FLOWLOG_ID_MAX)
	var err error
	var tables []*ckdb.Table
	if replicaEnabled {
		tables = GetFlowLogTables(ckdb.ReplicatedMergeTree)
	} else {
		tables = GetFlowLogTables(ckdb.MergeTree)
	}
	for i, table := range tables {
		counterName := "app_flow_log"
		if table.ID == uint8(common.L4_FLOW_ID) {
			counterName = "flow_log"
		}
		ckwriters[i], err = ckwriter.NewCKWriter(primaryAddr, secondaryAddr, user, password, counterName, table, replicaEnabled,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriters[i].Run()
	}

	return &FlowLogWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *FlowLogWriter) Put(index int, items ...interface{}) {
	w.ckwriters[index].Put(items...)
}

func (w *FlowLogWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
