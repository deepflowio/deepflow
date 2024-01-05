/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package service

import (
	"context"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
)

type OffloadQuerierable struct {
	queryType    model.QueryType
	args         *model.PromQueryParams
	reader       *prometheusReader
	querier      *OffloadQuerier
	keyGenerator func(model.QueryRequest) string

	queryStats        []model.PromQueryStats
	queryRequest      []model.QueryRequest
	mapToQueryRequest map[string]model.QueryRequest
	cachedQueryExprs  map[parser.Expr]func(parser.Expr)
}

type OffloadQuerierableOpts func(*OffloadQuerierable)

func NewOffloadQueriable(args *model.PromQueryParams, opts ...OffloadQuerierableOpts) *OffloadQuerierable {
	o := &OffloadQuerierable{args: args}
	if o.args.Debug {
		o.queryStats = make([]model.PromQueryStats, 0)
	}
	for _, opt := range opts {
		opt(o)
	}

	if len(o.queryRequest) > 0 {
		o.mapToQueryRequest = make(map[string]model.QueryRequest, len(o.queryRequest))
		for _, queryReq := range o.queryRequest {
			o.mapToQueryRequest[o.keyGenerator(queryReq)] = queryReq
		}

		o.cachedQueryExprs = make(map[parser.Expr]func(parser.Expr))
	}

	o.querier = &OffloadQuerier{
		querierable:  o,
		ctx:          o.args.Context,
		keyGenerator: o.keyGenerator,
		startTime:    o.args.StartTime,
		endTime:      o.args.EndTime,
		debug:        o.args.Debug,
	}

	return o
}

func WithQueryType(queryType model.QueryType) OffloadQuerierableOpts {
	return func(o *OffloadQuerierable) {
		o.queryType = queryType
	}
}

func WithQueryRequests(queryReq []model.QueryRequest) OffloadQuerierableOpts {
	return func(o *OffloadQuerierable) {
		o.queryRequest = queryReq
	}
}

func WithPrometheuReader(reader *prometheusReader) OffloadQuerierableOpts {
	return func(o *OffloadQuerierable) {
		o.reader = reader
	}
}

func WithKeyGenerator(generator func(model.QueryRequest) string) OffloadQuerierableOpts {
	return func(o *OffloadQuerierable) {
		o.keyGenerator = generator
	}
}

func (o *OffloadQuerierable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	return o.querier, nil
}

func (o *OffloadQuerierable) GetSQLQuery() []model.PromQueryStats {
	return o.queryStats
}

func (o *OffloadQuerierable) BindSelectedCallBack(q promql.Query) {
	o.querier.selectedCallback = func(queryType model.QueryType) error {
		stmt := q.Statement()
		if stmt, ok := stmt.(*parser.EvalStmt); ok {
			o.changeFunctionAfterOffloadSelected(stmt, queryType)
		}
		return nil
	}
}

func (o *OffloadQuerierable) AfterQueryExec(promql.Query) {
	o.restoreFunctionAfterQueryFinished()
}

// we've already do aggregation in database query, so we need to return result to frontend directly
// e.g.: count(node_cpu_seconds_total), we do `Count` in database, get `10` for count(node_cpu_seconds_total)
// but in prometheus engine, it recognise the aggregate function is `count`, it will count data samples, and we can not escape this second-aggregation
// so end up it gets samples count as `1`, which is wrong.
// the better way now is to change aggregate function, change count to sum, finally it will return `10` to the frontend, which is the correct result as our expected
func (o *OffloadQuerierable) changeFunctionAfterOffloadSelected(stmt *parser.EvalStmt, queryType model.QueryType) {
	parser.Inspect(stmt.Expr, func(node parser.Node, path []parser.Node) error {
		switch n := node.(type) {
		case *parser.AggregateExpr:
			switch n.Op {
			case parser.COUNT:
				if !n.Without {
					o.cachedQueryExprs[n] = parseAggToSum(n, n.Op, parser.SUM)
				}
			}
		case *parser.Call:
			switch n.Func.Name {
			case "irate":
				o.cachedQueryExprs[n] = parseCallToLastOverTime(n, n.Func.Name, "last_over_time")
			case "stddev_over_time":
				if queryType == model.Instant {
					o.cachedQueryExprs[n] = parseCallToLastOverTime(n, n.Func.Name, "last_over_time")
				}
			}
		}
		return nil
	})
}

// the way to restore the real function calculation, because promql engine has functional cache for the same promql
func parseAggToSum(n *parser.AggregateExpr, oriOp parser.ItemType, afterOp parser.ItemType) func(parser.Expr) {
	n.Op = afterOp
	return func(e parser.Expr) {
		if a, ok := e.(*parser.AggregateExpr); ok {
			a.Op = oriOp
		}
	}
}

func parseCallToLastOverTime(n *parser.Call, oriFunc string, afterFunc string) func(parser.Expr) {
	n.Func.Name = afterFunc
	return func(e parser.Expr) {
		if a, ok := e.(*parser.Call); ok {
			a.Func.Name = oriFunc
		}
	}
}

// why restore: expr would have a cache for the same promql
func (o *OffloadQuerierable) restoreFunctionAfterQueryFinished() {
	for expr, restoreFunc := range o.cachedQueryExprs {
		restoreFunc(expr)
	}
}

type OffloadQuerier struct {
	ctx              context.Context
	querierable      *OffloadQuerierable
	keyGenerator     func(model.QueryRequest) string
	selectedCallback func(model.QueryType) error

	debug              bool
	startTime, endTime string
}

func (o *OffloadQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	// get query Request by hint
	promtheusHint := &prometheusHint{hints: hints, matchers: matchers}
	queryReq := o.querierable.mapToQueryRequest[o.keyGenerator(promtheusHint)]

	//lint:ignore SA1029 use string as context key, ensure no type reference to app/prometheus
	ctx := context.WithValue(o.ctx, "remote_read", true)
	querierSql := o.querierable.reader.parseQueryRequestToSQL(ctx, queryReq, o.querierable.queryType)
	if querierSql != "" {
		result, sql, duration, err := queryDataExecute(ctx, querierSql, common.DB_NAME_PROMETHEUS, "", o.debug)
		if err != nil {
			log.Error(err)
			log.Errorf("offload querier sql: %s", querierSql)
			return storage.ErrSeriesSet(err)
		}
		if o.debug {
			o.querierable.queryStats = append(o.querierable.queryStats, model.PromQueryStats{SQL: sql, QuerierSQL: querierSql, Duration: duration})
		}
		startS, endS := queryReq.GetStart()/1e3, queryReq.GetEnd()/1e3
		// when use offloading query, it's always prometheus native metrics, with df_ prefix
		ctx = context.WithValue(ctx, ctxKeyPrefixType{}, prefixDeepFlow)
		resp, err := o.querierable.reader.respTransToProm(ctx, queryReq.GetMetric(), startS, endS, result)
		if err != nil {
			log.Error(err)
			return storage.ErrSeriesSet(err)
		}

		err = o.selectedCallback(o.querierable.queryType)
		if err != nil {
			// not return, selected callback only fixed query exprs
			log.Error(err)
		}

		return remote.FromQueryResult(sortSeries, resp.Results[0])
	}

	// else: querierSql == "", offload failed, try normal query
	// same to queryable.go#63 <func.Select>
	startTimeS, err := parseTime(o.startTime)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	endTimeS, err := parseTime(o.endTime)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	prompbQuery, err := remote.ToQuery(startTimeS.UnixMilli(), endTimeS.UnixMilli(), matchers, hints)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	req := &prompb.ReadRequest{
		Queries:               []*prompb.Query{prompbQuery},
		AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
	}
	resp, querierSql, sql, duration, err := o.querierable.reader.promReaderExecute(o.ctx, req, o.debug)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	if o.debug {
		o.querierable.queryStats = append(o.querierable.queryStats, model.PromQueryStats{SQL: sql, QuerierSQL: querierSql, Duration: duration})
	}
	return remote.FromQueryResult(sortSeries, resp.Results[0])
}

func (o *OffloadQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (o *OffloadQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (q *OffloadQuerier) Close() error {
	return nil
}
