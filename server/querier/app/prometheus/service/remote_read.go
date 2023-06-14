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
	logging "github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
)

var log = logging.MustGetLogger("promethues")

func promReaderExecute(req *prompb.ReadRequest, ctx context.Context) (resp *prompb.ReadResponse, err error) {
	// promrequest trans to sql
	// pp.Println(req)
	ctx, sql, db, datasource, err := PromReaderTransToSQL(ctx, req)
	// fmt.Println(sql, db)
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
		Debug:      strconv.FormatBool(config.Cfg.Prometheus.RequestQueryWithDebug),
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
	}
	// start span trace query time of any query uuid
	var span trace.Span
	if config.Cfg.Prometheus.RequestQueryWithDebug {
		tr := otel.GetTracerProvider().Tracer("querier/prometheus/clickhouseQuery")
		ctx, span = tr.Start(ctx, "PromReaderExecute",
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(attribute.String("query_uuid", query_uuid.String())))
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
		query_time := extractDebugInfoFromQueryResponse(debug)
		span.SetAttributes(attribute.Float64("query_time", query_time))
		span.End()
	}

	// response trans to prom resp
	resp, err = RespTransToProm(ctx, result)
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
