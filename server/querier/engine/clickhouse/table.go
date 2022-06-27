package clickhouse

import (
	"strings"

	"github.com/metaflowys/metaflow/server/querier/config"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/client"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/common"
)

func GetDatabases() map[string][]interface{} {
	var values []interface{}
	for db := range common.DB_TABLE_MAP {
		values = append(values, []string{db})
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}

func GetTables(db string) map[string][]interface{} {
	var values []interface{}
	tables, ok := common.DB_TABLE_MAP[db]
	if !ok {
		return nil
	}
	if db == "ext_metrics" {
		chClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       db,
		}
		err := chClient.Init("")
		if err != nil {
			log.Error(err)
			return nil
		}
		sql := "show tables"
		rst, err := chClient.DoQuery(sql, nil)
		if err != nil {
			log.Error(err)
			return nil
		}
		for _, _table := range rst["values"] {
			table := _table.([]interface{})[0].(string)
			if !strings.HasSuffix(table, "_local") {
				values = append(values, []string{table})
			}
		}
	} else {
		for _, table := range tables {
			values = append(values, []string{table})
		}
	}
	return map[string][]interface{}{
		"columns": []interface{}{"name"},
		"values":  values,
	}
}
