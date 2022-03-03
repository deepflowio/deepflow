package service

import (
	"metaflow/querier/engine"
	"metaflow/querier/engine/clickhouse"
)

func Execute(args map[string]string) (resp []string, err error) {
	db := getDbByIP(args["IP"])
	var engine engine.Engine
	switch db {
	case "clickhouse":
		engine = &clickhouse.CHEngine{IP: args["IP"]}
		engine.Init()
	}
	resp, err = engine.ExecuteQuery(args["sql"])

	return resp, err
}

func getDbByIP(IP string) string {
	return "clickhouse"
}
