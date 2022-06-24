package dbwriter

import (
	"server/libs/ckdb"
	"server/libs/pool"
	"server/libs/zerodoc"
)

type ExtMetrics struct {
	Timestamp uint32 // s

	Tag zerodoc.Tag

	TableName string

	TagNames  []string
	TagValues []string

	MetricsIntNames  []string
	MetricsIntValues []int64

	MetricsFloatNames  []string
	MetricsFloatValues []float64
}

func (m *ExtMetrics) WriteBlock(block *ckdb.Block) error {
	if err := m.Tag.WriteBlock(block, m.Timestamp); err != nil {
		return err
	}

	if err := block.WriteArrayString(m.TagNames); err != nil {
		return err
	}
	if err := block.WriteArrayString(m.TagValues); err != nil {
		return err
	}
	if err := block.WriteArrayString(m.MetricsIntNames); err != nil {
		return err
	}
	if err := block.WriteArray(m.MetricsIntValues); err != nil {
		return err
	}
	if err := block.WriteArrayString(m.MetricsFloatNames); err != nil {
		return err
	}
	if err := block.WriteArray(m.MetricsFloatValues); err != nil {
		return err
	}

	return nil
}

func (m *ExtMetrics) Columns() []*ckdb.Column {
	columns := zerodoc.GenTagColumns(m.Tag.Code)
	columns = append(columns,
		ckdb.NewColumn("tag_names", ckdb.ArrayString).SetComment("额外的tag"),
		ckdb.NewColumn("tag_values", ckdb.ArrayString).SetComment("额外的tag对应的值"),
		ckdb.NewColumn("metrics_int_names", ckdb.ArrayString).SetComment("额外的int类型metrics"),
		ckdb.NewColumn("metrics_int_values", ckdb.ArrayInt64).SetComment("额外的int metrics值"),
		ckdb.NewColumn("metrics_float_names", ckdb.ArrayString).SetComment("额外的float类型metrics"),
		ckdb.NewColumn("metrics_float_values", ckdb.ArrayFloat64).SetComment("额外的float metrics值"),
	)
	return columns
}

func (m *ExtMetrics) Release() {
	ReleaseExtMetrics(m)
}

func (m *ExtMetrics) GenCKTable(ttl int) *ckdb.Table {
	timeKey := "time"
	cluster := ckdb.DF_CLUSTER
	engine := ckdb.MergeTree

	orderKeys := []string{"l3_epc_id", "ip4", "ip6"}
	orderKeys = append(orderKeys, timeKey)

	return &ckdb.Table{
		Database:        EXT_METRICS_DB,
		LocalName:       m.TableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      m.TableName,
		Columns:         m.Columns(),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   ckdb.TimeFuncTwelveHour,
		Engine:          engine,
		Cluster:         cluster,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

var extMetricsPool = pool.NewLockFreePool(func() interface{} {
	return &ExtMetrics{
		Tag: zerodoc.Tag{
			Field: &zerodoc.Field{},
		},
		TagNames:           make([]string, 0, 4),
		TagValues:          make([]string, 0, 4),
		MetricsIntNames:    make([]string, 0, 4),
		MetricsIntValues:   make([]int64, 0, 4),
		MetricsFloatNames:  make([]string, 0, 4),
		MetricsFloatValues: make([]float64, 0, 4),
	}
})

func AcquireExtMetrics() *ExtMetrics {
	return extMetricsPool.Get().(*ExtMetrics)
}

func ReleaseExtMetrics(m *ExtMetrics) {
	*m.Tag.Field = zerodoc.Field{}
	m.TagNames = m.TagNames[:0]
	m.TagValues = m.TagValues[:0]
	m.MetricsIntNames = m.MetricsIntNames[:0]
	m.MetricsIntValues = m.MetricsIntValues[:0]
	m.MetricsFloatNames = m.MetricsFloatNames[:0]
	m.MetricsFloatValues = m.MetricsFloatValues[:0]
	extMetricsPool.Put(m)
}
