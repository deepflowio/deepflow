package metrics

import (
	"fmt"

	"github.com/metaflowys/metaflow/server/querier/config"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/client"
)

var EXT_METRICS = map[string]*Metrics{}

func GetExtMetrics(db, table string) (map[string]*Metrics, error) {
	loadMetrics := make(map[string]*Metrics)
	var err error
	if db == "ext_metrics" {
		externalChClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       db,
		}
		externalMetricIntSql := fmt.Sprintf("SELECT arrayJoin(metrics_int_names) AS metrics_int_name FROM (SELECT metrics_int_names FROM %s LIMIT 1) GROUP BY metrics_int_name", table)
		externalMetricFloatSql := fmt.Sprintf("SELECT arrayJoin(metrics_float_names) AS metrics_float_name FROM (SELECT metrics_float_names FROM %s LIMIT 1) GROUP BY metrics_float_name", table)
		externalMetricIntRst, err := externalChClient.DoQuery(externalMetricIntSql, nil, "")
		if err != nil {
			log.Error(err)
			return nil, err
		}
		externalMetricFloatRst, err := externalChClient.DoQuery(externalMetricFloatSql, nil, "")
		if err != nil {
			log.Error(err)
			return nil, err
		}
		for i, _tagName := range externalMetricIntRst["values"] {
			tagName := _tagName.([]interface{})[0]
			externalTag := tagName.(string)
			dbField := fmt.Sprintf("metrics_int_values[indexOf(metrics_int_names, '%s')]", externalTag)
			lm := NewMetrics(
				i, dbField, externalTag, "", METRICS_TYPE_COUNTER,
				"原始Tag", []bool{true, true, true}, externalTag,
				table,
			)
			loadMetrics[externalTag] = lm
		}
		for i, _tagName := range externalMetricFloatRst["values"] {
			tagName := _tagName.([]interface{})[0]
			externalTag := tagName.(string)
			dbField := fmt.Sprintf("metrics_float_values[indexOf(metrics_float_names, '%s')]", externalTag)
			lm := NewMetrics(
				i+len(externalMetricIntRst["values"]), dbField, externalTag, "", METRICS_TYPE_COUNTER,
				"原始Tag", []bool{true, true, true}, externalTag, table,
			)
			loadMetrics[externalTag] = lm
		}
	}
	return loadMetrics, err
}
