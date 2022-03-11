package service

import (
	"metaflow/querier/engine"
	"metaflow/querier/engine/clickhouse"
)

func Execute(args map[string]string) (resp map[string][]interface{}, err error) {
	db := getDbBy()
	var engine engine.Engine
	switch db {
	case "clickhouse":
		engine = &clickhouse.CHEngine{IP: args["ip"], DB: args["db"]}
		engine.Init()
	}
	resp, err = engine.ExecuteQuery(args["sql"])

	return resp, err
}

func getDbBy() string {
	return "clickhouse"
}
