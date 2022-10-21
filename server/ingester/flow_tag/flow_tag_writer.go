package flow_tag

import (
	"fmt"

	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/stats"
	"github.com/deepflowys/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("flow_tag.dbwriter")

type Counter struct {
	FieldCount      int64 `statsd:"field-count"`
	FieldValueCount int64 `statsd:"field-value-err"`
}

type FlowTagWriter struct {
	ckdbAddr     string
	ckdbUsername string
	ckdbPassword string
	writerConfig *config.CKWriterConfig

	ckwriters   [TagTypeMax]*ckwriter.CKWriter
	valueWriter *ckwriter.CKWriter

	counter *Counter
	utils.Closable
}

func NewFlowTagWriter(
	name string,
	srcDB string,
	ttl int,
	partition ckdb.TimeFuncType,
	config *config.Config,
	writerConfig *config.CKWriterConfig) (*FlowTagWriter, error) {
	w := &FlowTagWriter{
		ckdbAddr:     config.CKDB.ActualAddr,
		ckdbUsername: config.CKDBAuth.Username,
		ckdbPassword: config.CKDBAuth.Password,
		writerConfig: writerConfig,

		counter: &Counter{},
	}
	t := FlowTag{}
	var err error
	for _, tagType := range []TagType{TagField, TagFieldValue} {
		t.TableName = fmt.Sprintf("%s_%s", srcDB, tagType.String())
		t.hasFieldValue = false
		if tagType == TagFieldValue {
			t.hasFieldValue = true
		}
		w.ckwriters[tagType], err = ckwriter.NewCKWriter(w.ckdbAddr, "", w.ckdbUsername, w.ckdbPassword,
			fmt.Sprintf("%s_%s", name, t.TableName), t.GenCKTable(config.CKDB.ClusterName, config.CKDB.StoragePolicy, ttl, partition), false, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
		if err != nil {
			return nil, err
		}
		w.ckwriters[tagType].Run()
	}

	common.RegisterCountableForIngester("flow_tag_writer", w, stats.OptionStatTags{"type": name})
	return w, nil
}

func (w *FlowTagWriter) Write(t TagType, values ...interface{}) {
	w.ckwriters[t].Put(values...)
}

func (w *FlowTagWriter) WriteFieldsAndFieldValues(fields, fieldValues []interface{}) {
	if len(fields) != 0 {
		w.ckwriters[TagField].Put(fields...)
		w.counter.FieldCount += int64(len(fields))
	}

	if len(fieldValues) != 0 {
		w.ckwriters[TagFieldValue].Put(fieldValues...)
		w.counter.FieldValueCount += int64(len(fieldValues))
	}
}

func (w *FlowTagWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	return counter
}
