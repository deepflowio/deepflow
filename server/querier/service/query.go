package service

import (
	"server/querier/engine"
	"server/querier/engine/clickhouse"
)

func Execute(args map[string]string) (result map[string][]interface{}, debug map[string]interface{}, err error) {
	db := getDbBy()
	var engine engine.Engine
	switch db {
	case "clickhouse":
		engine = &clickhouse.CHEngine{DB: args["db"], DataSource: args["datasource"]}
		engine.Init()
	}
	result, debug, err = engine.ExecuteQuery(args["sql"], args["query_uuid"])

	return result, debug, err
}

func getDbBy() string {
	return "clickhouse"
}
