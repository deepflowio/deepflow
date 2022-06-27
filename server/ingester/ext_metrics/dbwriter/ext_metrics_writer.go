package dbwriter

import (
	"database/sql"
	"fmt"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/ingester/common"
	"github.com/metaflowys/metaflow/server/ingester/ext_metrics/config"
	"github.com/metaflowys/metaflow/server/ingester/pkg/ckwriter"
	"github.com/metaflowys/metaflow/server/libs/ckdb"
	"github.com/metaflowys/metaflow/server/libs/utils"
)

var log = logging.MustGetLogger("ext_metrics.dbwriter")

const (
	EXT_METRICS_DB   = "ext_metrics"
	QUEUE_BATCH_SIZE = 1024
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	PacketCount  int64 `statsd:"packet-count"`
	MetricsCount int64 `statsd:"metrics-count"`
	DecodeErr    int64 `statsd:"decode-err"`
	WriteErr     int64 `statsd:"write-err"`
}

type tableInfo struct {
	tableName string
	ckwriter  *ckwriter.CKWriter
}

type ExtMetricsWriter struct {
	ckdbAddr     string
	ckdbUsername string
	ckdbPassword string
	ttl          int
	writerConfig config.CKWriterConfig

	ckdbConn *sql.DB

	tables map[string]*tableInfo

	counter *Counter
	utils.Closable
}

func (w *ExtMetricsWriter) getOrCreateCkwriter(s *ExtMetrics) (*ckwriter.CKWriter, error) {
	if info, ok := w.tables[s.TableName]; ok {
		if info.ckwriter != nil {
			return info.ckwriter, nil
		}
	}

	if w.ckdbConn == nil {
		conn, err := common.NewCKConnection(w.ckdbAddr, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return nil, err
		}
		w.ckdbConn = conn
	}

	// 将要创建的表信息
	table := s.GenCKTable(w.ttl)

	ckwriter, err := ckwriter.NewCKWriter(w.ckdbAddr, "", w.ckdbUsername, w.ckdbPassword,
		s.TableName, table, false, w.writerConfig.QueueCount, w.writerConfig.QueueCount, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
	if err != nil {
		return nil, err
	}
	// 需要在cluseter其他节点也创建
	w.createTableOnCluster(table)

	ckwriter.Run()
	if w.ttl != config.DefaultExtMetricsTTL {
		w.setTTL(s.TableName)
	}

	w.tables[s.TableName] = &tableInfo{
		tableName: s.TableName,
		ckwriter:  ckwriter,
	}

	return ckwriter, nil
}

func (w *ExtMetricsWriter) createTableOnCluster(table *ckdb.Table) error {
	nodes, err := w.getClusterNodesWithoutLocal(table.Cluster.String())
	if err != nil {
		return err
	}
	for _, node := range nodes {
		err := ckwriter.InitTable(fmt.Sprintf("tcp://%s:%d", node.Addr, node.Port), w.ckdbUsername, w.ckdbPassword, table)
		if err != nil {
			log.Warningf("node %s:%d init table failed. err: %s", node.Addr, node.Port, err)
		} else {
			log.Infof("node %s:%d init table %s success", node.Addr, node.Port, table.LocalName)
		}
	}
	return nil
}

func (w *ExtMetricsWriter) getClusterNodesWithoutLocal(clusterName string) ([]ClusterNode, error) {
	sql := fmt.Sprintf("SELECT host_address,port,is_local FROM system.clusters WHERE cluster='%s'", clusterName)
	log.Info(sql)
	rows, err := w.ckdbConn.Query(sql)
	if err != nil {
		w.ckdbConn = nil
		return nil, err
	}
	var addr string
	var port uint16
	var isLocal uint8
	var clusterNodes = []ClusterNode{}
	for rows.Next() {
		err := rows.Scan(&addr, &port, &isLocal)
		if err != nil {
			return nil, err
		}
		if isLocal != 1 {
			clusterNodes = append(clusterNodes, ClusterNode{addr, port})
		}
	}
	return clusterNodes, nil
}

func (w *ExtMetricsWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	return counter
}

func (w *ExtMetricsWriter) setTTL(tableName string) error {
	sql := fmt.Sprintf("ALTER TABLE %s.%s MODIFY TTL time +  toIntervalDay(%d)",
		EXT_METRICS_DB, tableName+ckdb.LOCAL_SUBFFIX, w.ttl)
	log.Info(sql)
	_, err := w.ckdbConn.Exec(sql)
	return err
}

func (w *ExtMetricsWriter) Write(m *ExtMetrics) {
	ckwriter, err := w.getOrCreateCkwriter(m)
	if err != nil {
		if w.counter.WriteErr == 0 {
			log.Warningf("get writer failed:", err)
		}
		w.counter.WriteErr++
		return
	}
	w.counter.MetricsCount++
	ckwriter.Put(m)
}

func NewExtMetricsWriter(
	config *config.Config) *ExtMetricsWriter {
	writer := &ExtMetricsWriter{
		ckdbAddr:     config.Base.CKDB.Primary,
		ckdbUsername: config.Base.CKDBAuth.Username,
		ckdbPassword: config.Base.CKDBAuth.Password,
		tables:       make(map[string]*tableInfo),
		ttl:          config.TTL,
		writerConfig: config.CKWriterConfig,

		counter: &Counter{},
	}
	common.RegisterCountableForIngester("ext_metrics_writer", writer)
	return writer
}
