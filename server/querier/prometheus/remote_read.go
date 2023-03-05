package prometheus

import (
	"context"
	//"strings"
	//"strconv"
	//"time"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/google/uuid"
	//"github.com/k0kubun/pp"
	logging "github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
)

var log = logging.MustGetLogger("promethues")

func PromReaderExecute(req *prompb.ReadRequest, ctx context.Context) (resp *prompb.ReadResponse, err error) {
	// promrequest trans to sql
	//pp.Println(req)
	sql, db, datasource, err := PromReaderTransToSQL(req)
	//fmt.Println(sql, db)
	if err != nil {
		return nil, err
	}
	if db == "" {
		db = "ext_metrics"
	}
	query_uuid := uuid.New()
	args := common.QuerierParams{
		DB:         db,
		Sql:        sql,
		DataSource: datasource,
		Debug:      "false",
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
	}
	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(&args)
	if err != nil {
		// TODO
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debug, err)
		return nil, err
	}
	// response trans to prom resp
	resp, err = RespTransToProm(result)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	//pp.Println(resp)
	return resp, nil
}
