package datasource

import (
	"metaflow/querier/datasource/clickhouse"
)

func ExecuteQuery(args map[string]string) (resp []string, err error) {
	// 根据不同db类型进行解析和查询
	switch args["db"] {
	case "clickhouse":
		chq := clickhouse.CHQuery{IP: args["ip"]}
		resp, err = chq.Exec(args["sql"])
		return resp, err
	}
	return nil, nil
}
