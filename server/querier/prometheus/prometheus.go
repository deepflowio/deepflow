package prometheus

import (
	"context"
	"fmt"
	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse"
	"github.com/google/uuid"
	"github.com/prometheus/prometheus/prompb"
)

func PromReaderExecute(req *prompb.ReadRequest, ctx context.Context) (resp *prompb.ReadResponse, err error) {
	// promrequest trans to sql
	sql, err := PromReaderTransToSQL(req)
	if err != nil {
		return nil, err
	}
	query_uuid := uuid.New()
	args := common.QuerierParams{
		DB:         "ext_metrics",
		Sql:        sql,
		DataSource: "",
		Debug:      "false",
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
	}
	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(&args)
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
