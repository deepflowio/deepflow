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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql/parser"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/cache"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
)

// prometheusReader's lifecycle is belong to each query through api
type prometheusReader struct {
	slimit                  int
	orgID                   string
	extraFilters            string
	blockTeamID             []string
	interceptPrometheusExpr func(func(e *parser.AggregateExpr) error) error
	getExternalTagFromCache func(string, string) string
	addExternalTagToCache   func(string, string, string)
}

func (p *prometheusReader) promReaderExecute(ctx context.Context, req *prompb.ReadRequest, debug bool) (resp *prompb.ReadResponse, querierSql, sql string, duration float64, err error) {
	// promrequest trans to sql
	if req == nil || len(req.Queries) == 0 || req.Queries[0] == nil {
		return nil, "", "", 0, errors.New("len(req.Queries) == 0, this feature is not yet implemented! ")
	}
	if req.Queries[0].Hints == nil || req.Queries[0].Matchers == nil {
		return nil, "", "", 0, errors.New("req.Queries dont have hint or matchers! ")
	}
	start, end := cache.GetPromRequestQueryTime(req.Queries[0])
	metricName := cache.GetMetricFromLabelMatcher(&req.Queries[0].Matchers)
	cacheOrgFilterKey := fmt.Sprintf("%s-%s", p.orgID, strings.Join(p.blockTeamID, "-"))

	var response *prompb.ReadResponse
	// clear cache if data not found
	defer func(r *prompb.ReadRequest) {
		// when error occurs, means query not finished yet, remove the first query placeholder
		// if error is nil, means query finished, don't clean key
		if err != nil || response == nil {
			cache.PromReadResponseCache().Remove(r, cacheOrgFilterKey, p.extraFilters)
		}
	}(req)

	// should get cache result immediately
	// for DeepFlow Native metrics, don't use cache
	cacheAvailable := config.Cfg.Prometheus.Cache.RemoteReadCache && !strings.Contains(metricName, "__")
	if cacheAvailable {
		var hit cache.CacheHit
		var cacheItem *cache.CacheItem
		cacheItem, hit, start, end = cache.PromReadResponseCache().Get(req.Queries[0], start, end, cacheOrgFilterKey, p.extraFilters)
		if cacheItem != nil {
			response = cacheItem.Data()
		}

		if hit == cache.CacheKeyFoundNil && cacheItem != nil {
			// found item, but is loading by other request
			loadCompleted := cacheItem.GetLoadCompleteSignal()

			select {
			case <-time.After(time.Duration(config.Cfg.Prometheus.Cache.CacheFirstTimeout) * time.Second):
				log.Infof("req [%s:%d-%d] wait 10 seconds to get cache result", metricName, start, end)
				return response, "", "", 0, errors.New("query timeout, retry to get response! ")
			case <-loadCompleted:
				cacheItem, hit, start, end = cache.PromReadResponseCache().Get(req.Queries[0], start, end, cacheOrgFilterKey, p.extraFilters)
				if cacheItem != nil {
					response = cacheItem.Data()
				}
				log.Debugf("req [%s:%d-%d] get cached result", metricName, start, end)
			}
		}

		if hit == cache.CacheHitFull {
			return response, "", "", 0, nil
		}
	}

	// CacheKeyNotFound & CacheHitPart, do query
	var result *common.Result
	var db, datasource string
	var debugInfo map[string]interface{}
	log.Debugf("metric: [%s] data query range: [%d-%d]", metricName, start, end)
	ctx, querierSql, db, datasource, metricName, err = p.promReaderTransToSQL(ctx, req, start, end, debug)
	// fmt.Println(sql, db)
	if err != nil {
		return nil, "", "", 0, err
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
	args := common.QuerierParams{
		DB:         db,
		Sql:        querierSql,
		DataSource: datasource,
		Debug:      strconv.FormatBool(debug),
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
		ORGID:      p.orgID,
	}
	// get parentSpan for inject others attribute below
	parentSpan := trace.SpanFromContext(ctx)

	// start span trace query time of any query uuid
	var span trace.Span
	if debug {
		tr := otel.GetTracerProvider().Tracer("querier/prometheus/clickhouseQuery")
		ctx, span = tr.Start(ctx, "PromReaderExecute",
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(attribute.String("query_uuid", query_uuid.String())))

		defer span.End()
	}

	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debugInfo, err = ckEngine.ExecuteQuery(&args)
	if err != nil {
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debugInfo, err)
		return nil, "", "", 0, err
	}

	if debug {
		duration, sql = extractDebugInfoFromQueryResponse(debugInfo)

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

	api_query_start, api_query_end := cache.GetPromRequestQueryTime(req.Queries[0])
	// response trans to prom resp
	resp, err = p.respTransToProm(ctx, metricName, api_query_start, api_query_end, result)

	if cacheAvailable {
		// merge result into cache
		response = cache.PromReadResponseCache().AddOrMerge(req, resp, cacheOrgFilterKey, p.extraFilters)
	} else {
		// not using cache, query result would be real result
		response = resp
	}

	if err != nil {
		log.Error(err)
		return nil, "", "", 0, err
	}
	// pp.Println(resp)
	return response, querierSql, sql, duration, nil
}

// extract query_time from query debug(map[string]interface{}) infos
func extractDebugInfoFromQueryResponse(debug map[string]interface{}) (float64, string) {
	if debug["query_sqls"] != nil {
		debug_info, ok := debug["query_sqls"].([]client.Debug)
		if !ok || len(debug_info) == 0 {
			return 0, ""
		}
		// xxxs to number
		query_time, _ := strconv.ParseFloat(strings.ReplaceAll(debug_info[0].QueryTime, "s", ""), 64)
		return query_time, debug_info[0].Sql
	}
	return 0, ""
}

func queryDataExecute(ctx context.Context, querierSql string, db string, ds string, orgID string, debug bool) (*common.Result, string, float64, error) {
	var sql string
	var duration float64
	query_uuid := uuid.New()
	args := common.QuerierParams{
		DB:         db,
		Sql:        querierSql,
		DataSource: ds,
		Debug:      strconv.FormatBool(debug),
		QueryUUID:  query_uuid.String(),
		Context:    ctx,
		ORGID:      orgID,
	}
	// trace clickhouse query
	var span trace.Span
	if debug {
		tracer := otel.GetTracerProvider().Tracer("querier/prometheus/clickhouse/query")
		args.Context, span = tracer.Start(ctx, "PrometheusQueryDataExecute",
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(attribute.String("query_uuid", query_uuid.String())),
		)

		defer span.End()
	}
	ckEngine := &clickhouse.CHEngine{DB: args.DB, DataSource: args.DataSource}
	ckEngine.Init()
	result, debugInfo, err := ckEngine.ExecuteQuery(&args)
	if debug && debugInfo != nil {
		duration, sql = extractDebugInfoFromQueryResponse(debugInfo)

		span.SetAttributes(attribute.Float64("duration", duration))
		span.SetAttributes(attribute.String("querier_sql", querierSql))
		span.SetAttributes(attribute.String("sql", sql))
	}
	if err != nil {
		log.Errorf("ExecuteQuery failed, debug info = %v, err info = %v", debug, err)
		return nil, sql, duration, err
	}

	return result, sql, duration, err
}
