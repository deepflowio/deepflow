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
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	//"github.com/k0kubun/pp"
	pmmodel "github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/config"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	tagdescription "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
)

// The Series API supports returning the following time series (metrics):
// - Prometheus native metrics: directly return the existing metrics in Prometheus in the format of ${metrics_name}, for example
//    - demo_cpu_usage_seconds_total
// - DeepFlow metrics: Return all metrics by ${db_name}__${table_name}__${time_granularity}__${metrics_name}, where you need to replace . in metrics_name with _ to return, for example
//    - flow_log__l7_flow_log__rrt
//    - flow_metrics__vtap_flow_port__1m__rtt
//    - ext_metrics__metrics__prometheus_demo_cpu_usage_seconds_total
//    - ext_metrics__metrics__influxdb_cpu

// Note that as can be seen from the above description, Prometheus native metrics actually return twice.

// For the above two types of metrics, return the labels they support:
// - Prometheus native metrics
//    - Return the tag that has been injected in the Prometheus data, that is, the tag name in the tag_names column in ClickHouse, without the prefix `tag_`, for example: instance, pod
//    - Return the resource tags automatically injected by DeepFlow, including cloud resources, K8s pod resources, etc., and add `df_` prefix before the original tag name, for example: df_vpc, df_pod
//    - Return the automatically associated business labels in DeepFlow, including K8s label, etc., and add `df_` prefix before the original label name (and replace . with _), for example: df_k8s_label_env
// - DeepFlow metrics: use the tag name returned by the show tag API and replace . with _
//    - Return the injected tags in Prometheus/InfluxDB data, for example: tag_instance, tag_pod
//    - Returns the resource tags automatically injected by DeepFlow, including cloud resources, K8s pod resources, etc., for example: vpc, pod
//    - Returns the automatically associated business labels in DeepFlow, including K8s label, etc., for example: k8s_label_env

// Through this design, we mainly hope to achieve the following goals:
// - The Grafana Dashboard of Prometheus does not need to be modified, and the tags automatically added in DeepFlow can be used in these Dashboards
// - The Dashboard created by the user can directly use DeepFlow metrics, and there is no need to change the label name automatically added by DeepFlow when switching between different metrics

const _SUCCESS = "success"

// executors for prometheus query
type prometheusExecutor struct {
	extraLabelCache *lru.Cache[string, string]
	ticker          *time.Ticker
	lookbackDelta   time.Duration
}

func NewPrometheusExecutor(delta time.Duration) *prometheusExecutor {
	executor := &prometheusExecutor{
		extraLabelCache: lru.NewCache[string, string](config.Cfg.Prometheus.ExternalTagCacheSize),
		lookbackDelta:   delta,
	}
	go executor.triggerLoadExternalTag()
	return executor
}

func (p *prometheusExecutor) triggerLoadExternalTag() {
	p.ticker = time.NewTicker(time.Duration(config.Cfg.Prometheus.ExternalTagLoadInterval) * time.Second)
	defer func() {
		p.ticker.Stop()
		if err := recover(); err != nil {
			go p.triggerLoadExternalTag()
		}
	}()
	for range p.ticker.C {
		p.loadExternalTagCache()
	}
}

// API Spec: https://prometheus.io/docs/prometheus/latest/querying/api/#instant-queries
func (p *prometheusExecutor) promQueryExecute(ctx context.Context, args *model.PromQueryParams, engine *promql.Engine) (result *model.PromQueryResponse, err error) {
	queryTime, err := parseTime(args.StartTime)
	if err != nil {
		return nil, err
	}
	if config.Cfg.Prometheus.RequestQueryWithDebug {
		var span trace.Span
		tr := otel.GetTracerProvider().Tracer("querier/app/PrometheusInstantQueryRequest")
		ctx, span = tr.Start(ctx, "PrometheusInstantQuery",
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(
				attribute.String("promql.query", args.Promql),
			),
		)
		// record query cost in span cost time
		defer span.End()
	}

	slimit := config.Cfg.Prometheus.SeriesLimit
	if slimitArgs, err := strconv.Atoi(args.Slimit); err == nil && slimitArgs < slimit {
		slimit = slimitArgs
	}
	reader := newPrometheusReader(slimit)
	reader.getExternalTagFromCache = p.convertExternalTagToQuerierAllowTag
	reader.addExternalTagToCache = p.addExtraLabelConvertion
	// instant query will hint default query range:
	// query.lookback-delta: https://github.com/prometheus/prometheus/blob/main/cmd/prometheus/main.go#L398
	queriable := &RemoteReadQuerierable{Args: args, Ctx: ctx, MatchMetricNameFunc: p.matchMetricName, reader: reader}
	qry, err := engine.NewInstantQuery(queriable, nil, args.Promql, queryTime)
	if qry == nil || err != nil {
		log.Error(err)
		return nil, err
	}
	queriable.reader.interceptPrometheusExpr = func(handleExpr func(e *parser.AggregateExpr) error) error {
		// `handleExpr` will called in `prometheus reader`
		return p.beforePrometheusCalculate(qry, handleExpr)
	}
	res := qry.Exec(ctx)
	if res.Err != nil {
		log.Error(res.Err)
		return nil, res.Err
	}
	result = &model.PromQueryResponse{
		Data:   &model.PromQueryData{ResultType: res.Value.Type(), Result: res.Value},
		Status: _SUCCESS,
	}
	if args.Debug {
		result.Stats = model.PromQueryStats{SQL: queriable.sql, QueryTime: queriable.query_time}
	}
	return result, err
}

func (p *prometheusExecutor) promQueryRangeExecute(ctx context.Context, args *model.PromQueryParams, engine *promql.Engine) (result *model.PromQueryResponse, err error) {
	start, err := parseTime(args.StartTime)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	end, err := parseTime(args.EndTime)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	step, err := parseDuration(args.Step)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if config.Cfg.Prometheus.RequestQueryWithDebug {
		var span trace.Span
		tr := otel.GetTracerProvider().Tracer("querier/app/PrometheusRangeQueryRequest")
		ctx, span = tr.Start(ctx, "PrometheusRangeQuery",
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(
				attribute.String("promql.query", args.Promql),
				attribute.Int64("promql.query.range", int64(end.Sub(start).Minutes())),
				attribute.Int64("promql.query.step", int64(step.Seconds())),
			),
		)
		defer span.End()
	}
	slimit := config.Cfg.Prometheus.SeriesLimit
	if slimitArgs, err := strconv.Atoi(args.Slimit); err == nil && slimitArgs < slimit {
		slimit = slimitArgs
	}
	reader := newPrometheusReader(slimit)
	reader.getExternalTagFromCache = p.convertExternalTagToQuerierAllowTag
	reader.addExternalTagToCache = p.addExtraLabelConvertion
	queriable := &RemoteReadQuerierable{Args: args, Ctx: ctx, MatchMetricNameFunc: p.matchMetricName, reader: reader}
	qry, err := engine.NewRangeQuery(queriable, nil, args.Promql, start, end, step)
	if qry == nil || err != nil {
		log.Error(err)
		return nil, err
	}
	queriable.reader.interceptPrometheusExpr = func(f func(e *parser.AggregateExpr) error) error {
		// `handleExpr` will called in `prometheus reader`
		return p.beforePrometheusCalculate(qry, f)
	}
	res := qry.Exec(ctx)
	if res.Err != nil {
		log.Error(res.Err)
		return nil, res.Err
	}
	result = &model.PromQueryResponse{
		Data:   &model.PromQueryData{ResultType: res.Value.Type(), Result: res.Value},
		Status: _SUCCESS,
	}
	if args.Debug {
		// if query with `debug` parmas, return sql & query time
		result.Stats = model.PromQueryStats{SQL: queriable.sql, QueryTime: queriable.query_time}
	}
	return result, err
}

func (p *prometheusExecutor) promRemoteReadExecute(ctx context.Context, req *prompb.ReadRequest) (resp *prompb.ReadResponse, err error) {
	// analysis for ReadRequest
	reader := newPrometheusReader(config.Cfg.Prometheus.SeriesLimit)
	reader.getExternalTagFromCache = p.convertExternalTagToQuerierAllowTag
	reader.addExternalTagToCache = p.addExtraLabelConvertion
	result, _, _, err := reader.promReaderExecute(ctx, req, false)
	return result, err
}

func parseDuration(s string) (time.Duration, error) {
	if d, err := strconv.ParseFloat(s, 64); err == nil {
		ts := d * float64(time.Second)
		if ts > float64(math.MaxInt64) || ts < float64(math.MinInt64) {
			return 0, fmt.Errorf("cannot parse %q to a valid duration. It overflows int64", s)
		}
		return time.Duration(ts), nil
	}
	if d, err := pmmodel.ParseDuration(s); err == nil {
		return time.Duration(d), nil
	}
	return 0, fmt.Errorf("cannot parse %q to a valid duration", s)
}

func parseMatchersParam(matchers []string) ([][]*labels.Matcher, error) {
	matcherSets := make([][]*labels.Matcher, 0, len(matchers))
	for _, s := range matchers {
		matchers, err := parser.ParseMetricSelector(s)
		if err != nil {
			return nil, err
		}
		matcherSets = append(matcherSets, matchers)
	}

OUTER:
	for _, ms := range matcherSets {
		for _, lm := range ms {
			if lm != nil && !lm.Matches("") {
				continue OUTER
			}
		}
		return nil, errors.New("match[] must contain at least one non-empty matcher")
	}
	if len(matcherSets) == 0 {
		return nil, errors.New("match[] must contain at least one non-empty matcher")
	}
	return matcherSets, nil
}

func parseTime(s string) (time.Time, error) {
	if t, err := strconv.ParseFloat(s, 64); err == nil {
		s, ns := math.Modf(t)
		ns = math.Round(ns*1000) / 1000
		return time.Unix(int64(s), int64(ns*float64(time.Second))).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("cannot parse %q to a valid timestamp", s)
}

// API Spec: https://prometheus.io/docs/prometheus/latest/querying/api/#finding-series-by-label-matchers
func (p *prometheusExecutor) series(ctx context.Context, args *model.PromQueryParams) (result *model.PromQueryResponse, err error) {
	start, err := parseTime(args.StartTime)
	if err != nil {
		log.Error("Parse StartTime failed: %v", err)
		return nil, err
	}
	end, err := parseTime(args.EndTime)
	if err != nil {
		log.Error("Parse EndTime failed: %v", err)
		return nil, err
	}

	if config.Cfg.Prometheus.RequestQueryWithDebug {
		var span trace.Span
		tr := otel.GetTracerProvider().Tracer("querier/app/PrometheusSeriesRequest")
		ctx, span = tr.Start(ctx, "PrometheusSeriesRequest",
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(
				attribute.String("promql.query.matchers", strings.Join(args.Matchers, ",")),
				attribute.Int64("promql.query.range", int64(end.Sub(start).Minutes())),
			),
		)
		defer span.End()
	}

	labelMatchers, err := parseMatchersParam(args.Matchers)
	// pp.Println(args.Matchers)
	// pp.Println(matcherSets)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	reader := newPrometheusReader(config.Cfg.Prometheus.SeriesLimit)
	reader.getExternalTagFromCache = p.convertExternalTagToQuerierAllowTag
	reader.addExternalTagToCache = p.addExtraLabelConvertion
	querierable := &RemoteReadQuerierable{Args: args, Ctx: ctx, MatchMetricNameFunc: p.matchMetricName, reader: reader}
	q, err := querierable.Querier(ctx, timestamp.FromTime(start), timestamp.FromTime(end))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	hints := &storage.SelectHints{
		Start: timestamp.FromTime(start),
		End:   timestamp.FromTime(end),
		Func:  "series", // There is no series function, this token is used for lookups that don't need samples.
	}

	var seriesSet storage.SeriesSet
	if len(labelMatchers) > 1 {
		var queryResultSets []storage.SeriesSet
		for _, matcher := range labelMatchers {
			// We need to sort this select results to merge (deduplicate) the series sets later.
			s := q.Select(true, hints, matcher...)
			queryResultSets = append(queryResultSets, s)
		}
		seriesSet = storage.NewMergeSeriesSet(queryResultSets, storage.ChainedSeriesMerge)
	} else {
		// At this point at least one match exists.
		seriesSet = q.Select(false, hints, labelMatchers[0]...)
	}
	metrics := []labels.Labels{}
	for seriesSet.Next() {
		metrics = append(metrics, seriesSet.At().Labels())
	}

	if seriesSet.Err() != nil {
		log.Error(seriesSet.Err())
		return nil, seriesSet.Err()
	}

	return &model.PromQueryResponse{Data: metrics, Status: _SUCCESS}, err
}

func (p *prometheusExecutor) parsePromQL(promQL string) (res *model.PromQueryWrapper, err error) {
	res = &model.PromQueryWrapper{}
	expr, err := parser.ParseExpr(promQL)
	if err != nil {
		res.OptStatus = "fail"
		res.Description = err.Error()
		return res, err
	}
	var dbs, tables, metrics, aggFuncs []string
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			pbMatchers := make([]*prompb.LabelMatcher, 0, 1)
			for _, m := range vs.LabelMatchers {
				if m.Name == PROMETHEUS_METRICS_NAME {
					// metric name is only expected
					pbMatchers = append(pbMatchers, &prompb.LabelMatcher{
						Type:  prompb.LabelMatcher_EQ,
						Name:  m.Name,
						Value: m.Value,
					})
					_, _, db, tableName, _, _, metric, err := parseMetric(pbMatchers)
					if err != nil {
						return err
					}
					dbs = appendWithoutDuplicated(&dbs, db)
					tables = appendWithoutDuplicated(&tables, tableName)
					metrics = appendWithoutDuplicated(&metrics, metric)
					break
				}
			}
		}
		// every node may have multiple aggregation path
		for _, p := range path {
			switch e := p.(type) {
			case *parser.AggregateExpr:
				aggFuncs = appendWithoutDuplicated(&aggFuncs, e.Op.String())
			case *parser.Call:
				aggFuncs = appendWithoutDuplicated(&aggFuncs, e.Func.Name)
			}
		}
		return err
	})
	res.OptStatus = _SUCCESS
	res.Data = []map[string]interface{}{
		{
			"db":      strings.Join(dbs, ","),
			"table":   strings.Join(tables, ","),
			"metric":  strings.Join(metrics, ","),
			"aggFunc": strings.Join(aggFuncs, ","),
		},
	}
	return res, err
}

func appendWithoutDuplicated(array *[]string, str string) []string {
	for _, v := range *array {
		if v == str {
			return *array
		}
	}
	*array = append(*array, str)
	return *array
}

func (p *prometheusExecutor) addExtraFilters(promQL string, filters map[string]string) (*model.PromQueryWrapper, error) {
	res := &model.PromQueryWrapper{}
	expr, err := parser.ParseExpr(promQL)
	if err != nil {
		res.OptStatus = "fail"
		res.Description = err.Error()
		return res, err
	}

	matchers := make([]*labels.Matcher, 0, len(filters))
	for k, v := range filters {
		matcher, err := labels.NewMatcher(labels.MatchEqual, k, v)
		if err != nil {
			res.OptStatus = "fail"
			res.Description = err.Error()
			return res, err
		}
		matchers = append(matchers, matcher)
	}

	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			vs.LabelMatchers = append(vs.LabelMatchers, matchers...)
		}
		return nil
	})
	res.OptStatus = _SUCCESS
	res.Data = []map[string]interface{}{{"query": expr.String()}}
	return res, nil
}

func (p *prometheusExecutor) matchMetricName(matchers *[]*labels.Matcher) string {
	var metric string
	for _, v := range *matchers {
		if v.Name == PROMETHEUS_METRICS_NAME {
			metric = v.Value
			break
		}
	}
	return metric
}

// handle promql Expression before prometheus calculate
// TODO: add more pre-calculation to avoid re-calculate in prometheus
func (p *prometheusExecutor) beforePrometheusCalculate(q promql.Query, f func(e *parser.AggregateExpr) error) error {
	switch s := q.Statement().(type) {
	case *parser.EvalStmt:
		switch e := s.Expr.(type) {
		case *parser.AggregateExpr:
			return f(e)
		}
	}
	return nil
}

func (p *prometheusExecutor) loadExternalTagCache() {
	// DeepFlow Source have same tag collections, so just try query 1 table to add all external tags
	showTags := fmt.Sprintf("show tags from %s", VTAP_FLOW_PORT_TABLE)
	data, err := tagdescription.GetTagDescriptions(chCommon.DB_NAME_FLOW_METRICS, VTAP_FLOW_PORT_TABLE, showTags, context.Background())
	if err != nil {
		log.Errorf("load external tag error when start up prometheus executor: %s", err)
		return
	}
	if data != nil {
		for _, value := range data.Values {
			values := value.([]interface{})
			// data.Columns definitions:
			// "columns": ["name","client_name","server_name","display_name","type","category","operators","permissions","description","related_tag"]
			// we need to get .[4] value, confirm len(values) >= 5
			if values == nil || len(values) < 5 {
				continue
			}
			if values[4].(string) != "map_item" {
				continue
			}
			tag := values[0].(string)
			p.addExtraLabelConvertion(formatTagName(tag), tag)
		}
	}
}

// convert external tag to querier tag
// e.g.: k8s_label_helm_sh_chart_0 to 'k8s.label/helm.sh-chart'
func (p *prometheusExecutor) convertExternalTagToQuerierAllowTag(displayTag string) string {
	var suffix string
	if strings.HasSuffix(displayTag, "_0") {
		suffix = "_0"
	} else if strings.HasSuffix(displayTag, "_1") {
		suffix = "_1"
	}
	cacheTag := strings.TrimSuffix(displayTag, suffix)
	querierTag, ok := p.extraLabelCache.Get(cacheTag)
	if ok {
		return fmt.Sprintf("%s%s", querierTag, suffix)
	}
	return ""
}

func (p *prometheusExecutor) addExtraLabelConvertion(displayTag string, querierTag string) {
	p.extraLabelCache.Add(displayTag, querierTag)
}
