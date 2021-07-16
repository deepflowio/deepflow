package dbwriter

import (
	"fmt"

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
	orderByHour := fmt.Sprintf("toStartOfHour(%s)", id.TimeKey())
	orderKeys := []string{orderByHour, "l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0", "server_port"}

	return &ckdb.Table{
		ID:              uint8(id),
		Database:        common.FLOW_LOG_DB,
		LocalName:       id.String() + "_local",
		GlobalName:      id.String(),
		Columns:         columns,
		TimeKey:         id.TimeKey(),
		Engine:          engine,
		PartitionFunc:   ckdb.TimeFuncYYYYMMDD,
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
		ckwriters[i], err = ckwriter.NewCKWriter(primaryAddr, secondaryAddr, user, password, "flow_log", table, replicaEnabled,
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

func (w *FlowLogWriter) Put(items ...interface{}) error {
	caches := [common.FLOWLOG_ID_MAX][]interface{}{}
	for i, _ := range caches {
		caches[i] = make([]interface{}, 0, CACHE_SIZE)
	}
	for _, item := range items {
		switch t := item.(type) {
		case *jsonify.FlowLogger:
			caches[common.L4_FLOW_ID] = append(caches[common.L4_FLOW_ID], item)
		case *jsonify.HTTPLogger:
			caches[common.L7_HTTP_ID] = append(caches[common.L7_HTTP_ID], item)
		case *jsonify.DNSLogger:
			caches[common.L7_DNS_ID] = append(caches[common.L7_DNS_ID], item)
		default:
			log.Warningf("unsupport item type %T", t)
		}
	}

	for i, cache := range caches {
		if len(cache) > 0 {
			w.ckwriters[i].Put(cache...)
		}
	}
	return nil
}

func (w *FlowLogWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
