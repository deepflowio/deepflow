package dbwriter

import (
	logging "github.com/op/go-logging"
	"server/libs/app"

	"server/libs/ckdb"
	"server/libs/zerodoc"
	"server/ingester/common"
	"server/ingester/pkg/ckwriter"
	"server/ingester/roze/config"
)

var log = logging.MustGetLogger("roze.dbwriter")

const (
	CACHE_SIZE = 10240
)

type DbWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func NewDbWriter(primaryAddr, secondaryAddr, user, password string, replicaEnabled bool, ckWriterCfg config.CKWriterConfig) (*DbWriter, error) {
	ckwriters := []*ckwriter.CKWriter{}
	engine := ckdb.MergeTree
	if replicaEnabled {
		engine = ckdb.ReplicatedMergeTree
	}
	tables := zerodoc.GetMetricsTables(engine, common.CK_VERSION)
	for _, table := range tables {
		counterName := "metrics_1m"
		if table.ID >= uint8(zerodoc.VTAP_FLOW_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_FLOW_EDGE_PORT_1S) {
			counterName = "metrics_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1S) {
			counterName = "app_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1M) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1M) {
			counterName = "app_1m"
		}
		ckwriter, err := ckwriter.NewCKWriter(primaryAddr, secondaryAddr, user, password, counterName, table, replicaEnabled,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriter.Run()
		ckwriters = append(ckwriters, ckwriter)
	}

	return &DbWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *DbWriter) Put(items ...interface{}) error {
	caches := [zerodoc.VTAP_TABLE_ID_MAX][]interface{}{}
	for i := range caches {
		caches[i] = make([]interface{}, 0, CACHE_SIZE)
	}
	for _, item := range items {
		doc, ok := item.(*app.Document)
		if !ok {
			log.Warningf("receive wrong type data %v", item)
			continue
		}
		id, err := doc.TableID()
		if err != nil {
			log.Warningf("doc table id not found. %v", doc)
			continue
		}
		caches[id] = append(caches[id], doc)
	}

	for i, cache := range caches {
		if len(cache) > 0 {
			w.ckwriters[i].Put(cache...)
		}
	}
	return nil
}

func (w *DbWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
