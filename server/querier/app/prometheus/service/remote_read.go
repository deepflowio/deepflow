/*
 * Copyright (c) 2023 Yunshan Networks
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
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql/parser"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
)

type prometheusReader struct {
	slimit                  int
	interceptPrometheusExpr func(func(e *parser.AggregateExpr) error) error
}

func newPrometheusReader(slimit int) *prometheusReader {
	return &prometheusReader{slimit: slimit}
}

func (p *prometheusReader) promReaderExecute(ctx context.Context, req *prompb.ReadRequest, debug bool) (resp *prompb.ReadResponse, sql string, duration float64, err error) {
	// promrequest trans to sql
	// pp.Println(req)
	ctx, sql, db, datasource, metricName, err := p.promReaderTransToSQL(ctx, req)
	// fmt.Println(sql, db)
	if err != nil {
		return nil, "", 0, err
	}
	if db == "" {
		db = "prometheus"
	}
	query_uuid := uuid.New()
	// mark query comes from promql
	if db == "prometheus" {
		//lint:ignore SA1029 use string as context key, ensure no `type` reference to app/prometheus
		ctx = context.WithValue(ctx, "remote_read", true)
	}
	// if `api` pass `debug` or config debug, get debug info from querier
	debugQuerier := debug || config.Cfg.Prometheus.RequestQueryWithDebug
	args := common.QuerierParams{
		DB:         db,
		Sql:        sql,
		DataSource: datasource,
		Debug:      strconv.FormatBool(debugQuerier),
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
	}
	// get parentSpan for inject others attribute below
	parentSpan := trace.SpanFromContext(ctx)

	// start span trace query time of any query uuid
	var span trace.Span
	if config.Cfg.Prometheus.RequestQueryWithDebug {
		tr := otel.GetTracerProvider().Tracer("querier/prometheus/clickhouseQuery")
		ctx, span = tr.Start(ctx, "PromReaderExecute",
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(attribute.String("query_uuid", query_uuid.String())))

		defer span.End()
	}

	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debugInfo, err := ckEngine.ExecuteQuery(&args)
	if err != nil {
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debugInfo, err)
		return nil, "", 0, err
	}

	if debugQuerier {
		duration = extractQueryTimeFromQueryResponse(debugInfo)
		sql = extractQuerySQLFromQueryResponse(debugInfo)
	}

	if config.Cfg.Prometheus.RequestQueryWithDebug {
		// inject query_time for current span
		span.SetAttributes(attribute.Float64("query_time", duration))

		// inject labels for parent span
		targetLabels := make([]string, 0, len(result.Schemas))
		appLabels := make([]string, 0, len(result.Schemas))
		for i := 0; i < len(result.Schemas); i++ {
			labelType := result.Schemas[i].LabelType
			if labelType == "app" {
				appLabels = append(appLabels, strings.TrimPrefix(result.Columns[i].(string), "tag."))
			} else if labelType == "target" {
				targetLabels = append(targetLabels, strings.TrimPrefix(result.Columns[i].(string), "tag."))
			}
		}
		if len(targetLabels) > 0 {
			parentSpan.SetAttributes(attribute.String("promql.query.metric.targetLabel", strings.Join(targetLabels, ",")))
		}
		if len(appLabels) > 0 {
			parentSpan.SetAttributes(attribute.String("promql.query.metric.appLabel", strings.Join(appLabels, ",")))
		}
	}

	// response trans to prom resp
	resp, err = p.respTransToProm(ctx, metricName, result)
	if err != nil {
		log.Error(err)
		return nil, "", 0, err
	}
	// pp.Println(resp)
	return resp, sql, duration, nil
}

// extract query_time from query debug(map[string]interface{}) infos
func extractQueryTimeFromQueryResponse(debug map[string]interface{}) float64 {
	if debug["query_time"] != nil {
		query_time_str := strings.ReplaceAll(debug["query_time"].(string), "s", "")
		query_time, _ := strconv.ParseFloat(query_time_str, 64)
		return query_time
	}
	return 0
}

func extractQuerySQLFromQueryResponse(debug map[string]interface{}) string {
	if debug["sql"] != nil {
		return debug["sql"].(string)
	}
	return ""
}

func queryDataExecute(ctx context.Context, sql string, db string, ds string) (*common.Result, error) {
	query_uuid := uuid.New()
	args := common.QuerierParams{
		DB:         db,
		Sql:        sql,
		DataSource: ds,
		Debug:      strconv.FormatBool(config.Cfg.Prometheus.RequestQueryWithDebug),
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
	}
	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(&args)
	if err != nil {
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debug, err)
		return nil, err
	}
	return result, err
}
