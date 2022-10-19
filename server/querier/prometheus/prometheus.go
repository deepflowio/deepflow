package prometheus

import (
	"fmt"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse"
	"github.com/google/uuid"
	"github.com/prometheus/prometheus/prompb"
)

func PromReaderExecute(req *prompb.ReadRequest) (resp *prompb.ReadResponse, err error) {
	// promrequest trans to sql
	sql, err := PromReaderTransToSQL(req)
	if err != nil {
		return nil, err
	}
	query_uuid := uuid.New()
	args := map[string]string{
		"db":         "ext_metrics",
		"sql":        sql,
		"datasource": "",
		"debug":      "false",
		"query_uuid": query_uuid.String(),
	}
	ckEngine := &clickhouse.CHEngine{DB: args["db"], DataSource: args["datasource"]}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(args["sql"], args["query_uuid"])
	if err != nil {
		// TODO
		fmt.Printf("%v %v", debug, err)
		return nil, err
	}
	// response trans to prom resp
	resp, err = RespTransToProm(result)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
