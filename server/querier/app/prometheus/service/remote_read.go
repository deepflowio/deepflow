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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
)

func promReaderExecute(ctx context.Context, req *prompb.ReadRequest) (resp *prompb.ReadResponse, err error) {
	// promrequest trans to sql
	// pp.Println(req)
	ctx, sql, db, datasource, err := promReaderTransToSQL(ctx, req)
	// fmt.Println(sql, db)
	if err != nil {
		return nil, err
	}
	if db == "" {
		db = "prometheus"
	}
	query_uuid := uuid.New()
	args := common.QuerierParams{
		DB:         db,
		Sql:        sql,
		DataSource: datasource,
		Debug:      strconv.FormatBool(config.Cfg.Prometheus.RequestQueryWithDebug),
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
	result, debug, err := ckEngine.ExecuteQuery(&args)
	if err != nil {
		// TODO
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debug, err)
		return nil, err
	}

	if config.Cfg.Prometheus.RequestQueryWithDebug {
		// inject query_time for current span
		query_time := extractDebugInfoFromQueryResponse(debug)
		span.SetAttributes(attribute.Float64("query_time", query_time))

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
	resp, err = respTransToProm(ctx, result)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	// pp.Println(resp)
	return resp, nil
}

// extract query_time from query debug(map[string]interface{}) infos
func extractDebugInfoFromQueryResponse(debug map[string]interface{}) float64 {
	if debug["query_time"] != nil {
		query_time_str := strings.ReplaceAll(debug["query_time"].(string), "s", "")
		query_time, _ := strconv.ParseFloat(query_time_str, 64)
		return query_time
	}
	return 0
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
