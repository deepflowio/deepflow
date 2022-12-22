package prometheus

import (
	"context"
	"fmt"
	"strconv"

	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse"
	"github.com/google/uuid"
	logging "github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
)

var log = logging.MustGetLogger("promethues")

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

func PromQueryExecute(args *common.PromQueryParams, ctx context.Context) (result *common.Result, debug map[string]interface{}, err error) {
	resps := []*prompb.ReadResponse{}
	expr, err := parser.ParseExpr(args.Promql)
	if err != nil {
		return nil, nil, err
	}
	timeS, err := (strconv.ParseFloat(args.Time, 64))
	if err != nil {
		return nil, nil, err
	}
	timeMs := int64(timeS * 1000)
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		switch selector := n.(type) {
		case *parser.VectorSelector:
			prompbQuery, err := remote.ToQuery(timeMs, timeMs, selector.LabelMatchers, &storage.SelectHints{
				Step:  1,
				Start: timeMs,
				End:   timeMs,
			})
			if err != nil {
				return err
			}
			req := &prompb.ReadRequest{
				Queries:               []*prompb.Query{prompbQuery},
				AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
			}
			resp, err := PromReaderExecute(req, ctx)
			if err != nil {
				return err
			}
			resps = append(resps, resp)
		}
		return nil
	})
	log.Infof("%+V", resps)
	// TODO 计算结果
	return result, debug, err
}

func PromQueryRangeExecute(args *common.PromQueryRangeParams, ctx context.Context) (result *common.Result, debug map[string]interface{}, err error) {
	resps := []*prompb.ReadResponse{}
	expr, err := parser.ParseExpr(args.Promql)
	if err != nil {
		return nil, nil, err
	}
	startS, err := (strconv.ParseFloat(args.StartTime, 64))
	if err != nil {
		return nil, nil, err
	}
	endS, err := (strconv.ParseFloat(args.EndTime, 64))
	if err != nil {
		return nil, nil, err
	}
	step, err := (strconv.ParseInt(args.Step, 10, 64))
	if err != nil {
		return nil, nil, err
	}
	startMs := int64(startS * 1000)
	endMs := int64(endS * 1000)

	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		switch selector := n.(type) {
		case *parser.VectorSelector:
			prompbQuery, err := remote.ToQuery(startMs, endMs, selector.LabelMatchers, &storage.SelectHints{
				Step:  step,
				Start: startMs,
				End:   endMs,
			})
			if err != nil {
				return err
			}
			req := &prompb.ReadRequest{
				Queries:               []*prompb.Query{prompbQuery},
				AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
			}
			resp, err := PromReaderExecute(req, ctx)
			if err != nil {
				return err
			}
			resps = append(resps, resp)
		}
		return nil
	})
	log.Infof("%+V", resps)
	// TODO 计算结果
	return result, debug, err
}
