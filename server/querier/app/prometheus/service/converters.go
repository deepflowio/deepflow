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
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	tagdescription "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

const (
	PROMETHEUS_METRICS_NAME    = "__name__"
	PROMETHEUS_NATIVE_TAG_NAME = "tag"
	PROMETHEUS_TIME_COLUMNS    = "timestamp"
	PROMETHEUS_METRIC_VALUE    = "value"
	PROMETHEUS_LABELS_INDEX    = "__labels_index__"
	ENUM_TAG_SUFFIX            = "_enum"

	FUNCTION_TOPK    = "topk"
	FUNCTION_BOTTOMK = "bottomk"
)

const (
	EXT_METRICS_TABLE         = "metrics"
	PROMETHEUS_TABLE          = "samples"
	L4_FLOW_LOG_TABLE         = "l4_flow_log"
	L7_FLOW_LOG_TABLE         = "l7_flow_log"
	VTAP_APP_PORT_TABLE       = "vtap_app_port"
	VTAP_FLOW_PORT_TABLE      = "vtap_flow_port"
	VTAP_APP_EDGE_PORT_TABLE  = "vtap_app_edge_port"
	VTAP_FLOW_EDGE_PORT_TABLE = "vtap_flow_edge_port"
)

const (
	// map tag will be extract in other tags
	// e.g.: tag `k8s.label` will extract in tag `k8s.label.app` (or other)
	IGNORABLE_TAG_TYPE = "map"
)

var QPSLeakyBucket *datastructure.LeakyBucket

// /querier/engine/clickhouse/clickhouse.go: `pod_ingress` and `lb_listener` are not supported by select
// `time` as tag is pointless
var ignorableTagNames = []string{"pod_ingress", "lb_listener", "time"}

var edgeTableNames = []string{
	VTAP_FLOW_EDGE_PORT_TABLE,
	VTAP_APP_EDGE_PORT_TABLE,
	L4_FLOW_LOG_TABLE,
	L7_FLOW_LOG_TABLE,
}

// rules for convert prom tag to native tag when query prometheus metrics
var matcherRules = map[string]string{
	"k8s_label_": "k8s.label.",
	"cloud_tag_": "cloud.tag.",
}

// definition: https://github.com/prometheus/prometheus/blob/main/promql/parser/lex.go#L106
// docs: https://prometheus.io/docs/prometheus/latest/querying/operators/#aggregation-operators
// convert promql aggregation functions to querier functions
var aggFunctions = map[string]string{
	"sum":          view.FUNCTION_SUM,
	"avg":          view.FUNCTION_AVG,
	"count":        view.FUNCTION_COUNT,
	"min":          view.FUNCTION_MIN,
	"max":          view.FUNCTION_MAX,
	"group":        "1", // all values in the resulting vector are 1
	"stddev":       view.FUNCTION_STDDEV,
	"stdvar":       "",                  // not supported
	"topk":         FUNCTION_TOPK,       // query sum value to avoid multiple values in one timestamp, it will aggregated by prometheus
	"bottomk":      FUNCTION_BOTTOMK,    // query sum value to avoid multiple values in one timestamp, it will aggregated by prometheus
	"count_values": view.FUNCTION_COUNT, // equals count() group by value in ck
	"quantile":     "",                  // not supported, FIXME: should support histogram in querier, and calcul Pxx by histogram
}

var _match_fullmatch_reg = regexp.MustCompile(`^[\w\|]+$`)

var _relabelFunctions = []string{"sum", "avg", "count", "min", "max", "group", "stddev", "stdvar", "count_values", "quantile"}

var _matrixCallFunctions = []string{"topk", "bottomk",
	"avg_over_time", "count_over_time", "last_over_time", "max_over_time", "min_over_time", "stddev_over_time", "sum_over_time", "present_over_time", "quantile_over_time",
	"idelta", "delta", "increase", "irate", "rate"}

// define `showtag` flag, it passed when and only [api/v1/series] been called
type CtxKeyShowTag struct{}

type prefix int

const (
	prefixNone     prefix = iota
	prefixDeepFlow        // support "df_" prefix for DeepFlow universal tag, e.g.: df_auto_instance
	prefixTag             // support "tag_" prefix for Prometheus native lable, e.g.: tag_instance
)

type ctxKeyPrefixType struct{}

func (p *prometheusReader) promReaderTransToSQL(ctx context.Context, req *prompb.ReadRequest, startTime int64, endTime int64) (context.Context, string, string, string, string, error) {
	// QPS Limit Check
	// Both SetRate and Acquire are expanded by 1000 times, making it suitable for small QPS scenarios.
	if !QPSLeakyBucket.Acquire(1000) {
		return ctx, "", "", "", "", errors.New("Prometheus query rate exceeded!")
	}

	queriers := req.Queries
	if len(queriers) < 1 {
		return ctx, "", "", "", "", errors.New("len(req.Queries) == 0, this feature is not yet implemented!")
	}
	q := queriers[0]

	prefixType, metricName, db, table, dataPrecision, metricAlias, queryMetric, err := parseMetric(q.Matchers)
	ctx = context.WithValue(ctx, ctxKeyPrefixType{}, prefixType)
	if err != nil {
		return ctx, "", "", "", "", err
	}

	metricsArray := []string{fmt.Sprintf("toUnixTimestamp(time) AS %s", PROMETHEUS_TIME_COLUMNS)}
	orderBy := []string{fmt.Sprintf("%s desc", PROMETHEUS_TIME_COLUMNS)}
	var groupBy []string
	var metricWithAggFunc string
	// use map for duplicate tags removal
	var expectedDeepFlowNativeTags map[string]string

	// append query field: 1. show tags OR aggregation tags
	isShowTagStatement := false
	if st, ok := ctx.Value(CtxKeyShowTag{}).(bool); ok {
		isShowTagStatement = st
	}
	if isShowTagStatement {
		tagsArray, err := showTags(ctx, db, table, startTime, endTime)
		if err != nil {
			return ctx, "", "", "", "", err
		}
		// append all `SHOW tags`
		metricsArray = append(metricsArray, tagsArray...)
		expectedDeepFlowNativeTags = make(map[string]string, len(q.Matchers)-1)
	} else {
		if db != DB_NAME_EXT_METRICS && db != DB_NAME_DEEPFLOW_SYSTEM && db != chCommon.DB_NAME_PROMETHEUS && db != "" {
			// DeepFlow native metrics needs aggregation for query
			if len(q.Hints.Grouping) == 0 {
				// not specific cardinality
				return ctx, "", "", "", "", fmt.Errorf("unknown series")
			}
			if !q.Hints.By {
				// not support for `without` operation
				return ctx, "", "", "", "", fmt.Errorf("not support for 'without' clause for aggregation")
			}

			aggOperator := aggFunctions[q.Hints.Func]
			if aggOperator == "" {
				return ctx, "", "", "", "", fmt.Errorf("aggregation operator: %s is not supported yet", q.Hints.Func)
			}

			// time query per step
			if q.Hints.StepMs > 0 {
				// range query, aggregation for time step
				// rebuild `time` in range query, replace `toUnixTimestamp(time) as timestamp`
				// time(time, x) means aggregation with time by interval x
				// calculate `offset` for range query
				offset := q.Hints.StartMs % q.Hints.StepMs
				metricsArray[0] = fmt.Sprintf("time(time, %d, 1, 0, %d) AS %s", q.Hints.StepMs/1e3, offset/1e3, PROMETHEUS_TIME_COLUMNS)
			}

			groupBy = make([]string, 0, len(q.Hints.Grouping)+1)
			// instant query only aggerate to 1 timestamp point
			groupBy = append(groupBy, PROMETHEUS_TIME_COLUMNS)

			// should append all labels in query & grouping clause
			for _, groupLabel := range q.Hints.Grouping {
				tagName, tagAlias, _ := p.parsePromQLTag(prefixType, db, groupLabel)

				if tagAlias == "" {
					groupBy = append(groupBy, tagName)
					metricsArray = append(metricsArray, tagName)
				} else {
					groupBy = append(groupBy, tagAlias)
					metricsArray = append(metricsArray, fmt.Sprintf("%s as %s", tagName, tagAlias))
				}
			}

			// aggregation for metrics, assert aggOperator is not empty
			switch aggOperator {
			case view.FUNCTION_SUM, view.FUNCTION_AVG, view.FUNCTION_MIN, view.FUNCTION_MAX, view.FUNCTION_STDDEV:
				metricWithAggFunc = fmt.Sprintf("%s(`%s`)", aggOperator, metricName)
			case "1":
				// group
				metricWithAggFunc = aggOperator
			case view.FUNCTION_COUNT:
				metricWithAggFunc = "Count(row)" // will be append as `metrics.$metricsName` in below

				// count_values means count unique value
				if q.Hints.Func == "count_values" {
					metricsArray = append(metricsArray, fmt.Sprintf("`%s`", metricName)) // append original metric name
					groupBy = append(groupBy, fmt.Sprintf("`%s`", metricName))
				} else {
					// for [Count], not calculate second times, just return Count(row) value
					if p.interceptPrometheusExpr != nil {
						_ = p.interceptPrometheusExpr(func(e *parser.AggregateExpr) error {
							// Count(row) in deepflow already complete in clickhouse query
							// so we don't need `Count` again, instead, `Sum` all `Count` result would be our expectation
							// so, modify expr.Operation here to make prometheus engine do `Sum` for `values`
							e.Op = parser.SUM
							return nil
						})
					}
				}
			// in `topk`/`bottomk`, we `Sum` all value by grouping tag as datasource
			case FUNCTION_TOPK:
				metricWithAggFunc = fmt.Sprintf("Sum(`%s`)", metricName)
				orderBy = append(orderBy, "value desc")
			case FUNCTION_BOTTOMK:
				metricWithAggFunc = fmt.Sprintf("Sum(`%s`)", metricName)
				orderBy = append(orderBy, "value asc")
			}
		} else {
			if len(q.Hints.Grouping) > 0 {
				expectedDeepFlowNativeTags = make(map[string]string, len(q.Hints.Grouping)+len(q.Matchers)-1)
				for _, q := range q.Hints.Grouping {
					tagName, tagAlias, isDeepFlowTag := p.parsePromQLTag(prefixType, db, q)
					if isDeepFlowTag {
						expectedDeepFlowNativeTags[tagName] = tagAlias
					}
				}
			} else {
				expectedDeepFlowNativeTags = make(map[string]string, len(q.Matchers)-1)
			}
		}
	}

	// append query field: 2. append metric name
	if db == "" || db == chCommon.DB_NAME_PROMETHEUS {
		// append metricName `value`
		metricsArray = append(metricsArray, metricAlias)
		// append `tag` only for prometheus & ext_metrics & deepflow_system
		if !common.IsValueInSliceString(q.Hints.Func, _relabelFunctions) {
			// `tag` should be append into `Select` with:
			// 1. not any aggregations, try get all `tag`
			// 2. topk(n)/bottomk(n) get all `tag`
			// 3. when argTypes == Matrix, get all `tag`. i.e.: irate/rate/x_over_time
			metricsArray = append(metricsArray, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
		} else {
			metricsArray = append(metricsArray, fmt.Sprintf("FastTrans(%s) as %s", PROMETHEUS_NATIVE_TAG_NAME, PROMETHEUS_LABELS_INDEX))
			for _, g := range q.Hints.Grouping {
				tagName, tagAlias, _ := p.parsePromQLTag(prefixType, db, g)

				if tagAlias == "" {
					metricsArray = append(metricsArray, tagName)
				} else {
					metricsArray = append(metricsArray, fmt.Sprintf("%s as %s", tagName, tagAlias))
				}
			}
		}
	} else if db == chCommon.DB_NAME_EXT_METRICS || db == chCommon.DB_NAME_DEEPFLOW_SYSTEM {
		metricsArray = append(metricsArray, fmt.Sprintf(metricAlias, metricName))
		metricsArray = append(metricsArray, fmt.Sprintf("`%s`", PROMETHEUS_NATIVE_TAG_NAME))
	} else {
		// for flow_metrics/flow_log/deepflow_system/ext_metrics
		// append metricName as "%s as value"
		if metricWithAggFunc != "" {
			// only when query metric samples
			metricsArray = append(metricsArray, fmt.Sprintf(metricAlias, metricWithAggFunc))
		} else {
			// only when query series
			metricsArray = append(metricsArray, fmt.Sprintf(metricAlias, metricName))
		}
	}

	// append query field: 3. append filter tags
	filters := make([]string, 0, len(q.Matchers)+1)
	filters = append(filters, fmt.Sprintf("(time >= %d AND time <= %d)", startTime, endTime))
	for _, matcher := range q.Matchers {
		if matcher.Name == PROMETHEUS_METRICS_NAME {
			continue
		}
		operation, value := getLabelMatcher(matcher.Type, matcher.Value)
		if operation == "" {
			return ctx, "", "", "", "", fmt.Errorf("unknown match type %v", matcher.Type)
		}

		tagName, tagAlias, isDeepFlowTag := p.parsePromQLTag(prefixType, db, matcher.Name)
		// for normal query & DeepFlow metrics, query enum tag can only use tag name(Enum(x)) in filter clause
		tagMatcher := tagName
		if prefixType != prefixNone && isDeepFlowTag && tagAlias != "" {
			// for Prometheus metrics, query DeepFlow enum tag can only use tag alias(x_enum) in filter clause
			tagMatcher = tagAlias
		}

		if len(value) > 1 {
			tmpFilters := make([]string, 0, len(value))
			for _, v := range value {
				tmpFilters = append(tmpFilters, fmt.Sprintf("%s %s '%s'", tagMatcher, operation, v))
			}
			filters = append(filters, fmt.Sprintf("(%s)", strings.Join(tmpFilters, " OR ")))
		} else {
			// () with only ONE condition in it will cause error
			filters = append(filters, fmt.Sprintf("%s %s '%s'", tagMatcher, operation, value[0]))
		}

		if db == "" || db == chCommon.DB_NAME_PROMETHEUS || db == chCommon.DB_NAME_EXT_METRICS {
			if isDeepFlowTag {
				if len(q.Hints.Grouping) == 0 || tagAlias != "" {
					expectedDeepFlowNativeTags[tagName] = tagAlias
				}
			} else if config.Cfg.Prometheus.RequestQueryWithDebug {
				// append in query for analysis (findout if tag is target_label)
				expectedDeepFlowNativeTags[tagName] = tagAlias
			}
		}
	}

	// append query field: 4. append DeepFlow native tags for Prometheus metrics
	for tagName, tagAlias := range expectedDeepFlowNativeTags {
		// reduce Prometheus query DeepFlow tags
		// append tags into `select` clause only when:
		// 1. grouping DeepFlow tags or filter DeepFlow tags
		// 2. filer enum tags when grouping
		// will not append tags:
		// 1. neither grouping nor filter any DeepFlow tags
		// 2. filter normal tags when grouping
		if tagAlias == "" {
			metricsArray = append(metricsArray, tagName)
		} else {
			metricsArray = append(metricsArray, fmt.Sprintf("%s as %s", tagName, tagAlias))
		}
	}

	sql := parseToQuerierSQL(ctx, db, table, metricsArray, filters, groupBy, orderBy)
	return ctx, sql, db, dataPrecision, queryMetric, err
}

// return: prefixType, metricName, db, table, dataPrecision, metricAlias
// prefixType: identified if use `tag_` or `df_` prefix in labels for prometheus native metrics
// metricName: real metric in database
// db table dataPrecision: database infomation
// metricAlias: identified how to query metric alias in `select` clause
// queryMetric: query metric in the input of label matcher
func parseMetric(matchers []*prompb.LabelMatcher) (prefixType prefix, metricName string, db string, table string, dataPrecision string, metricAlias string, queryMetric string, err error) {
	// get metric_name from the matchers
	for _, matcher := range matchers {
		if matcher.Name != PROMETHEUS_METRICS_NAME {
			continue
		}
		metricName = matcher.Value
		queryMetric = matcher.Value

		if strings.Contains(metricName, "__") {
			// DeepFlow native metrics: ${db}__${table}__${metricsName}
			// i.e.: flow_log__l4_flow_log__byte_rx
			// DeepFlow native metrics(flow_metrics): ${db}__${table}__${metricsName}__${datasource}
			// i.e.: flow_metrics__vtap_flow_port__byte_rx__1m
			// Telegraf integrated metrics: ext_metrics__metrics__${integratedSource}_${inputTarget}__${metricsName}
			// i.e.: ext_metrics__metrics__influxdb_cpu__usage_user
			// Prometheus integrated metrics: prometheus__samples__${metricsName}
			// i.e.: prometheus__samples__node_cpu_seconds_total
			metricsSplit := strings.Split(metricName, "__")
			if _, ok := chCommon.DB_TABLE_MAP[metricsSplit[0]]; ok {
				db = metricsSplit[0]
				table = metricsSplit[1] // FIXME: should fix deepflow_system table name like 'deepflow_server.xxx'
				metricName = metricsSplit[2]

				if db == DB_NAME_DEEPFLOW_SYSTEM {
					metricAlias = "`metrics.%s` as value"
				} else if db == DB_NAME_EXT_METRICS {
					// identify tag prefix as "tag_"
					prefixType = prefixTag
					// convert prometheus_xx/influxdb_xx to prometheus.xxx/influxdb.xx (split to 2 parts)
					realMetrics := strings.SplitN(metricName, "_", 2)
					if len(realMetrics) > 1 {
						table = fmt.Sprintf("%s.%s", realMetrics[0], realMetrics[1])
						if realMetrics[0] == "influxdb" {
							metricName = metricsSplit[3]
						} else {
							metricName = realMetrics[1]
						}
					}
					metricAlias = "`metrics.%s` as value"
				} else if db == chCommon.DB_NAME_PROMETHEUS {
					prefixType = prefixTag
					// query `prometheus`.`samples` table, should query metrics
					table = metricName
					metricAlias = "value"
				} else {
					// To identify which columns belong to metrics, we identified all metric value as `value`
					metricAlias = "%s as value"
				}

				// data precision only available for 'flow_metrics'
				if len(metricsSplit) > 3 && db == DB_NAME_FLOW_METRICS {
					dataPrecision = metricsSplit[3]
				}
			} else {
				return prefixType, "", "", "", "", "", "", fmt.Errorf("unknown metrics %v", metricName)
			}
		} else {
			// Prometheus native metrics: ${metricsName}
			// identify prefix for tag names with "df_"
			prefixType = prefixDeepFlow

			// Prometheus native metrics only query `value` as metrics sample
			metricAlias = "value"
			table = metricName
		}
		break
	}
	return
}

func showTags(ctx context.Context, db string, table string, startTime int64, endTime int64) ([]string, error) {
	showTags := "SHOW tags FROM %s.%s WHERE time >= %d AND time <= %d"
	var data *common.Result
	var err error
	var tagsArray []string
	if db == "" || db == chCommon.DB_NAME_PROMETHEUS {
		data, err = tagdescription.GetTagDescriptions(chCommon.DB_NAME_PROMETHEUS, PROMETHEUS_TABLE, fmt.Sprintf(showTags, chCommon.DB_NAME_PROMETHEUS, PROMETHEUS_TABLE, startTime, endTime), ctx)
	} else if db == chCommon.DB_NAME_EXT_METRICS {
		data, err = tagdescription.GetTagDescriptions(chCommon.DB_NAME_EXT_METRICS, EXT_METRICS_TABLE, fmt.Sprintf(showTags, chCommon.DB_NAME_EXT_METRICS, EXT_METRICS_TABLE, startTime, endTime), ctx)
	} else {
		data, err = tagdescription.GetTagDescriptions(db, table, fmt.Sprintf(showTags, db, table, startTime, endTime), ctx)
	}
	if err != nil || data == nil {
		return tagsArray, err
	}

	if common.IsValueInSliceString(table, edgeTableNames) {
		tagsArray = make([]string, 0, len(data.Values)*2)
	} else {
		tagsArray = make([]string, 0, len(data.Values))
	}

	for _, value := range data.Values {
		// data.Columns definitions:
		// "columns": ["name","client_name","server_name","display_name","type","category","operators","permissions","description","related_tag"]
		// i.e.: columns[i] defines name of values[i]
		values := value.([]interface{})
		if values == nil {
			continue
		}
		tagName := values[0].(string)
		if common.IsValueInSliceString(tagName, ignorableTagNames) {
			continue
		}
		clientTagName := values[1].(string)
		serverTagName := values[2].(string)
		tagType := values[4].(string)

		if tagType == IGNORABLE_TAG_TYPE {
			continue
		}

		// `edgeTable` storage data which contains both client and server-side, so metrics should cover both, else only one of them
		// e.g.: auto_instance_0/auto_instance_1 in `vtap_app_edge_port`, auto_instance in `vtap_app_port`
		if common.IsValueInSliceString(table, edgeTableNames) && tagName != clientTagName {
			// tagType=int_enum/string_enum
			if strings.Contains(tagType, ENUM_TAG_SUFFIX) {
				clientTagName = fmt.Sprintf("Enum(`%s`) as `%s%s`", clientTagName, clientTagName, ENUM_TAG_SUFFIX)
				serverTagName = fmt.Sprintf("Enum(`%s`) as `%s%s`", serverTagName, serverTagName, ENUM_TAG_SUFFIX)
				tagsArray = append(tagsArray, clientTagName, serverTagName)
			} else {
				tagsArray = append(tagsArray, fmt.Sprintf("`%s`", clientTagName))
				tagsArray = append(tagsArray, fmt.Sprintf("`%s`", serverTagName))
			}
		} else {
			if strings.Contains(tagType, ENUM_TAG_SUFFIX) {
				tagName = fmt.Sprintf("Enum(`%s`) as `%s%s`", tagName, tagName, ENUM_TAG_SUFFIX)
				tagsArray = append(tagsArray, tagName)
			} else {
				tagsArray = append(tagsArray, fmt.Sprintf("`%s`", tagName))
			}
		}
	}

	return tagsArray, nil
}

func parseDeepFlowTag(prefixType prefix, tag string) (tagName string, tagAlias string) {
	if enumAlias, ok := formatEnumTag(tag); ok {
		return enumAlias, fmt.Sprintf("`%s%s`", tag, ENUM_TAG_SUFFIX)
	} else {
		tagName = fmt.Sprintf("`%s`", tag)
	}
	return tagName, tagAlias
}

func parsePrometheusTag(tag string) string {
	return fmt.Sprintf("`tag.%s`", tag)
}

func (p *prometheusReader) parsePromQLTag(prefixType prefix, db, tag string) (tagName string, tagAlias string, isDeepFlowTag bool) {
	switch prefixType {
	case prefixTag:
		// query ext_metrics/prometheus
		if strings.HasPrefix(tag, "tag_") {
			tagName = parsePrometheusTag(removeTagPrefix(tag))
			isDeepFlowTag = false
		} else {
			tagName, tagAlias = parseDeepFlowTag(prefixType, p.convertToQuerierAllowedTagName(tag))
			isDeepFlowTag = true
		}
	case prefixDeepFlow:
		// query prometheus native metrics
		if strings.HasPrefix(tag, config.Cfg.Prometheus.AutoTaggingPrefix) {
			tagName, tagAlias = parseDeepFlowTag(prefixType, p.convertToQuerierAllowedTagName(removeDeepFlowPrefix(tag)))
			isDeepFlowTag = true
		} else {
			tagName = parsePrometheusTag(removeTagPrefix(tag))
			isDeepFlowTag = false
		}
	default:
		// query deepflow native metrics (deepflow_system/flow_metrics/flow_log)
		if db == chCommon.DB_NAME_DEEPFLOW_SYSTEM {
			tagName = parsePrometheusTag(tag)
		} else {
			tagName, tagAlias = parseDeepFlowTag(prefixType, p.convertToQuerierAllowedTagName(tag))
		}
		isDeepFlowTag = true
	}
	// `tagAlias` return only when tag is `enum tag`
	return
}

func parseToQuerierSQL(ctx context.Context, db string, table string, metrics []string, filters []string, groupBy []string, orderBy []string) (sql string) {
	// order by DESC for get data completely, then scan data reversely for data combine(see func.RespTransToProm)
	// querier will be called later, so there is no need to display the declaration db
	if db != "" {
		sqlBuilder := strings.Builder{}
		sqlBuilder.WriteString(fmt.Sprintf("SELECT %s FROM `%s` WHERE %s ", strings.Join(metrics, ","), table, strings.Join(filters, " AND ")))
		if len(groupBy) > 0 {
			sqlBuilder.WriteString("GROUP BY " + strings.Join(groupBy, ","))
		}
		sqlBuilder.WriteString(fmt.Sprintf(" ORDER BY %s LIMIT %s", strings.Join(orderBy, ","), config.Cfg.Prometheus.Limit))
		sql = sqlBuilder.String()
	} else {
		sql = fmt.Sprintf("SELECT %s FROM `%s` WHERE %s ORDER BY %s LIMIT %s", strings.Join(metrics, ","),
			table, // equals prometheus metric name
			strings.Join(filters, " AND "),
			strings.Join(orderBy, ","), config.Cfg.Prometheus.Limit)
	}
	return
}

// querier result trans to Prom Response
func (p *prometheusReader) respTransToProm(ctx context.Context, metricsName string, start, end int64, result *common.Result) (resp *prompb.ReadResponse, err error) {
	if result == nil || len(result.Values) == 0 {
		return &prompb.ReadResponse{Results: []*prompb.QueryResult{{}}}, nil
	}
	log.Debugf("resTransToProm: result length: %d", len(result.Values))
	tagIndex := -1
	metricsIndex := -1
	timeIndex := -1
	otherTagCount := 0
	labelsIndex := -1
	tagsFieldIndex := make(map[int]bool, len(result.Columns))
	prefix, _ := ctx.Value(ctxKeyPrefixType{}).(prefix) // ignore if key not exist
	for i, tag := range result.Columns {
		if tag == PROMETHEUS_NATIVE_TAG_NAME {
			tagIndex = i
		} else if strings.HasPrefix(tag.(string), "tag.") {
			tagsFieldIndex[i] = true
		} else if tag == PROMETHEUS_METRIC_VALUE {
			metricsIndex = i
		} else if tag == PROMETHEUS_TIME_COLUMNS {
			timeIndex = i
		} else if tag == PROMETHEUS_LABELS_INDEX {
			labelsIndex = i
		} else {
			otherTagCount++
		}
	}
	if metricsIndex < 0 || timeIndex < 0 {
		return nil, fmt.Errorf("metricsIndex(%d), timeIndex(%d) get failed", metricsIndex, timeIndex)
	}
	metricsType := result.Schemas[metricsIndex].ValueType

	// append other deepflow native tag into results
	allDeepFlowNativeTags := make([]int, 0, otherTagCount)
	for i := range result.Columns {
		if i == tagIndex || i == metricsIndex || i == timeIndex || i == labelsIndex || tagsFieldIndex[i] {
			continue
		}
		allDeepFlowNativeTags = append(allDeepFlowNativeTags, i)
	}

	// Scan all the results, determine the seriesID of each sample and the number of samples in each series,
	// so that the size of the sample array in each series can be determined in advance.
	maxPossibleSeries := len(result.Values)
	if maxPossibleSeries > p.slimit {
		maxPossibleSeries = p.slimit
	}

	seriesIndexMap := map[string]int32{}                            // the index in seriesArray, for each `tagsJsonStr`
	seriesArray := make([]*prompb.TimeSeries, 0, maxPossibleSeries) // series storage
	sampleSeriesIndex := make([]int32, len(result.Values))          // the index in seriesArray, for each sample
	seriesSampleCount := make([]int32, maxPossibleSeries)           // number of samples of each series
	initialSeriesIndex := int32(0)
	promJsonMap := make(map[string]map[string]string)
	tagsStrList := make([]string, 0, len(allDeepFlowNativeTags))
	promTagStrList := make([]string, 0)
	promTagWriter := strings.Builder{}

	for i, v := range result.Values {
		values := v.([]interface{})
		// don't append series if it's outside query time range
		currentTimestamp := int64(values[timeIndex].(int))
		if currentTimestamp < start || currentTimestamp > end {
			continue
		}

		// merge and serialize all tags as map key
		var deepflowNativeTagString, promTagJson string
		var filterTagMap map[string]string
		// merge prometheus tags
		if tagIndex > -1 {
			promTagJson = values[tagIndex].(string)
			var ok bool
			if filterTagMap, ok = promJsonMap[promTagJson]; !ok {
				filterTagMap = make(map[string]string)
				json.Unmarshal([]byte(promTagJson), &filterTagMap)
			}
			if cap(promTagStrList) < len(filterTagMap) {
				promTagStrList = make([]string, 0, len(filterTagMap))
			}
			for k, v := range filterTagMap {
				if k == "" || v == "" {
					continue
				}
				// ignore replica labels if passed
				if config.Cfg.Prometheus.ThanosReplicaLabels != nil && common.IsValueInSliceString(k, config.Cfg.Prometheus.ThanosReplicaLabels) {
					filterTagMap[k] = ""
					continue
				}
				filterTagMap[k] = v
				promTagStrList = append(promTagStrList, k)
			}
			promJsonMap[promTagJson] = filterTagMap
			sort.Strings(promTagStrList)
			for i := 0; i < len(promTagStrList); i++ {
				promTagWriter.WriteString(promTagStrList[i])
				promTagWriter.WriteByte(':')
				promTagWriter.WriteString(filterTagMap[promTagStrList[i]])
			}
			deepflowNativeTagString = promTagWriter.String()
			promTagWriter.Reset()
			promTagStrList = promTagStrList[:0]
		} else if labelsIndex > -1 {
			labelsArray, ok := values[labelsIndex].([]uint32)
			if !ok {
				log.Errorf("parse app_label_index_x failed, real type is: %s", reflect.TypeOf(values[labelsIndex]).Kind())
				continue
			}
			labelString := strings.Builder{}
			for j := 0; j < len(labelsArray); j++ {
				labelString.WriteString(strconv.Itoa(j))
				labelString.WriteString(strconv.Itoa(int(labelsArray[j])))
			}
			deepflowNativeTagString = labelString.String()
			filterTagMap = make(map[string]string, len(tagsFieldIndex)+1)
			filterTagMap[PROMETHEUS_LABELS_INDEX] = deepflowNativeTagString

			// agg prometheus query, directly get tag.x
			for idx := range tagsFieldIndex {
				name := strings.Replace(result.Columns[idx].(string), "tag.", "", 1)
				val := values[idx].(string)

				if name == "" || val == "" {
					continue
				}
				// ignore replica labels if passed
				if config.Cfg.Prometheus.ThanosReplicaLabels != nil && common.IsValueInSliceString(name, config.Cfg.Prometheus.ThanosReplicaLabels) {
					continue
				}
				filterTagMap[name] = val
			}
		}

		if deepflowNativeTagString == "" {
			deepflowNativeTagString = fmt.Sprintf("%s:%s", PROMETHEUS_METRICS_NAME, metricsName)
			if filterTagMap == nil {
				filterTagMap = map[string]string{PROMETHEUS_METRICS_NAME: metricsName}
			} else {
				filterTagMap[PROMETHEUS_METRICS_NAME] = metricsName
			}
		}

		// merge deepflow autotagging tags
		if len(allDeepFlowNativeTags) > 0 {
			for i := 0; i < len(allDeepFlowNativeTags); i++ {
				tagsStrList = append(tagsStrList, strconv.Itoa(allDeepFlowNativeTags[i]))
				tagsStrList = append(tagsStrList, getValue(values[allDeepFlowNativeTags[i]]))
			}
			deepflowNativeTagString += strings.Join(tagsStrList, "-")
			tagsStrList = tagsStrList[:0]
		}

		// check and assign seriesIndex
		var series *prompb.TimeSeries
		index, exist := seriesIndexMap[deepflowNativeTagString]
		if exist {
			sampleSeriesIndex[i] = index
			seriesSampleCount[index]++
		} else {
			if len(seriesIndexMap) >= p.slimit {
				sampleSeriesIndex[i] = -1
				continue
			}

			// tag label pair
			var pairs []prompb.Label
			if len(filterTagMap) > 0 {
				pairs = make([]prompb.Label, 0, 1+len(filterTagMap)+len(allDeepFlowNativeTags))
				for k, v := range filterTagMap {
					if v == "" {
						continue
					}
					if prefix == prefixTag {
						// prometheus tag for deepflow metrics
						pairs = append(pairs, prompb.Label{Name: appendPrometheusPrefix(k), Value: v})
					} else {
						// no prefix, use prometheus native tag
						pairs = append(pairs, prompb.Label{Name: k, Value: v})
					}
				}

			}

			if cap(pairs) == 0 {
				pairs = make([]prompb.Label, 0, 1+len(allDeepFlowNativeTags))
			}

			for _, idx := range allDeepFlowNativeTags {
				// remove zero value tag (0/""/{})
				if isZero(values[idx]) {
					continue
				}
				formatTag := formatTagName(result.Columns[idx].(string))
				p.addExternalTagCache(formatTag, result.Columns[idx].(string))

				if len(filterTagMap) > 0 && prefix == prefixDeepFlow {
					// deepflow tag for prometheus metrics
					pairs = append(pairs, prompb.Label{Name: appendDeepFlowPrefix(extractEnumTag(formatTag)), Value: getValue(values[idx])})
				} else {
					pairs = append(pairs, prompb.Label{Name: extractEnumTag(formatTag), Value: getValue(values[idx])})
				}
			}

			// append the special tag: "__name__": "$metricsName"
			if len(pairs) == 0 {
				continue
			}
			pairs = append(pairs, prompb.Label{
				Name:  PROMETHEUS_METRICS_NAME,
				Value: metricsName,
			})
			series = &prompb.TimeSeries{Labels: pairs}
			seriesArray = append(seriesArray, series)

			seriesIndexMap[deepflowNativeTagString] = initialSeriesIndex
			sampleSeriesIndex[i] = initialSeriesIndex
			seriesSampleCount[initialSeriesIndex] = 1
			initialSeriesIndex++
		}
	}

	// reverse scan, make data order by time asc for prometheus filter handling (happens in prometheus PromQL engine)
	for i := len(result.Values) - 1; i >= 0; i-- {
		if sampleSeriesIndex[i] == -1 {
			continue // SLIMIT overflow
		}

		// get metrics
		values := result.Values[i].([]interface{})
		// don't append series if it's outside query time range
		currentTimestamp := int64(values[timeIndex].(int))
		if currentTimestamp < start || currentTimestamp > end {
			continue
		}

		if values[metricsIndex] == nil {
			continue
		}

		if metricsType != "Int" && metricsType != "Float64" {
			return nil, fmt.Errorf("unknown metrics type %s, value = %v ", metricsType, values[metricsIndex])
		}

		metricsValue, ok := parseValue(metricsType, values[metricsIndex])
		if !ok {
			continue
		}

		// add a sample for the TimeSeries
		seriesIndex := sampleSeriesIndex[i]
		series := seriesArray[seriesIndex]
		if cap(series.Samples) == 0 {
			series.Samples = make([]prompb.Sample, 0, seriesSampleCount[seriesIndex])
		}
		currentTimestampMs := currentTimestamp * 1000
		// ignore repeat data points, it may cause calculation error by irate/idelta
		if len(series.Samples) > 0 && series.Samples[len(series.Samples)-1].Timestamp == currentTimestampMs {
			continue
		}
		series.Samples = append(
			series.Samples, prompb.Sample{
				Timestamp: currentTimestampMs,
				Value:     metricsValue,
			},
		)
	}

	// assemble the final prometheus response
	resp = &prompb.ReadResponse{
		Results: []*prompb.QueryResult{{}},
	}
	resp.Results[0].Timeseries = append(resp.Results[0].Timeseries, seriesArray...)
	return resp, nil
}

func convertTo[T int | float64](val interface{}) (v T, b bool) {
	v, b = val.(T)
	return
}

func parseValue(valueType string, val interface{}) (v float64, b bool) {
	switch valueType {
	case "Int":
		metricsValueInt, ok := convertTo[int](val)
		return float64(metricsValueInt), ok
	case "Float64":
		// metricsType == "Float64" but typeof(values[metricsIndex]) is `int` ?? for robustness add type assert
		metricsValueFloat, ok := convertTo[float64](val)
		if !ok {
			metricsValueInt, ok := convertTo[int](val)
			return float64(metricsValueInt), ok
		}
		return metricsValueFloat, ok
	default:
		return 0, false
	}
}

// match prometheus lable matcher type
func getLabelMatcher(t prompb.LabelMatcher_Type, v string) (string, []string) {
	switch t {
	case prompb.LabelMatcher_EQ:
		return "=", []string{v}
	case prompb.LabelMatcher_NEQ:
		return "!=", []string{v}
	case prompb.LabelMatcher_RE:
		// for regex like 'a|b', convert to 'tag=a OR tag=b'
		if _match_fullmatch_reg.MatchString(v) {
			return "=", strings.Split(v, "|")
		} else {
			return "REGEXP", []string{appendRegexRules(v)}
		}
	case prompb.LabelMatcher_NRE:
		// for regex like 'a|b', convert to 'tag!=a OR tag!=b'
		if _match_fullmatch_reg.MatchString(v) {
			return "!=", strings.Split(v, "|")
		} else {
			return "NOT REGEXP", []string{appendRegexRules(v)}
		}
	default:
		return "", []string{v}
	}
}

func appendRegexRules(v string) string {
	if len(v) > 0 {
		if !strings.HasPrefix(v, "^") {
			v = "^" + v
		}
		if !strings.HasSuffix(v, "$") {
			v = v + "$"
		}
		return v
	}
	return v
}

func getValue(value interface{}) string {
	switch val := value.(type) {
	case int:
		return strconv.Itoa(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case time.Time:
		return val.String()
	case nil:
		return ""
	default:
		return val.(string)
	}
}

func isZero(value interface{}) bool {
	switch val := value.(type) {
	case string:
		return val == "" || val == "{}"
	case int:
		return val == 0
	case nil:
		return true
	default:
		return false
	}
}

func extractEnumTag(tag string) string {
	if strings.HasSuffix(tag, ENUM_TAG_SUFFIX) {
		return strings.ReplaceAll(tag, ENUM_TAG_SUFFIX, "")
	}
	return tag
}

func formatEnumTag(tagName string) (string, bool) {
	// parse when query client/server side enum tag
	enumFile := strings.TrimSuffix(tagName, "_0")
	enumFile = strings.TrimSuffix(enumFile, "_1")
	if !common.IsValueInSliceString(tagName, tagdescription.NoLanguageTag) {
		enumFile = fmt.Sprintf("%s.%s", enumFile, config.Cfg.Language)
	}
	_, exists := tagdescription.TAG_ENUMS[enumFile]
	if exists {
		return fmt.Sprintf("Enum(%s)", tagName), exists
	}
	return tagName, exists
}

// k8s label character set: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
// prometheus label character set: https://prometheus.io/docs/concepts/data_model/
func formatTagName(tagName string) (newTagName string) {
	newTagName = strings.ReplaceAll(tagName, ".", "_")
	newTagName = strings.ReplaceAll(newTagName, "-", "_")
	newTagName = strings.ReplaceAll(newTagName, "/", "_")
	return newTagName
}

func (p *prometheusReader) addExternalTagCache(tag string, originTag string) {
	// we don't need to add all tags into cache
	if strings.Contains(tag, ".") || strings.Contains(tag, "-") || strings.Contains(tag, "/") {
		p.addExternalTagToCache(tag, originTag)
	}
}

func appendDeepFlowPrefix(tag string) string {
	return fmt.Sprintf("%s%s", config.Cfg.Prometheus.AutoTaggingPrefix, tag)
}

func appendPrometheusPrefix(tag string) string {
	return fmt.Sprintf("tag_%s", tag)
}

func (p *prometheusReader) convertToQuerierAllowedTagName(matcherName string) (tagName string) {
	if realTag := p.getExternalTagFromCache(matcherName); realTag != "" {
		return realTag
	} else {
		return matcherName
	}
}

func removeDeepFlowPrefix(tag string) string {
	return strings.TrimPrefix(tag, config.Cfg.Prometheus.AutoTaggingPrefix)
}

func removeTagPrefix(tag string) string {
	return strings.Replace(tag, "tag_", "", 1)
}
