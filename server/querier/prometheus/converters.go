package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	tagdescription "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
)

const (
	PROMETHEUS_METRICS_NAME     = "__name__"
	EXT_METRICS_NATIVE_TAG_NAME = "tag"
	EXT_METRICS_TIME_COLUMNS    = "timestamp"

	TAP_SIDE_TAG_NAME      = "tap_side"
	AUTO_INSTANCE_TAG_NAME = "auto_instance"
)
const (
	EXT_METRICS_TABLE         = "metrics"
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

// define `showtag` flag, it passed when and only [api/v1/series] been called
type CtxKeyShowTag struct{}

type prefix int

const (
	prefixNone     prefix = iota
	prefixDeepFlow        // support "df_" prefix for DeepFlow universal tag, e.g.: df_auto_instance
	prefixTag             // support "tag_" prefix for Prometheus native lable, e.g.: tag_instance
)

type ctxKeyPrefixType struct{}

func PromReaderTransToSQL(ctx context.Context, req *prompb.ReadRequest) (contxt context.Context, sql string, db string, datasource string, err error) {
	queriers := req.Queries
	if len(queriers) < 1 {
		// TODO
		return ctx, "", "", "", errors.New("len(req.Queries) == 0, this feature is not yet implemented!")
	}
	q := queriers[0]
	// pp.Println(q)

	startTime := q.Hints.StartMs / 1000
	endTime := q.Hints.EndMs / 1000
	if q.EndTimestampMs%1000 > 0 {
		endTime += 1
	}
	timeFilter := fmt.Sprintf("(time >= %d AND time <= %d)", startTime, endTime)
	filters := []string{timeFilter}
	metrics := []string{fmt.Sprintf("toUnixTimestamp(time) AS %s", EXT_METRICS_TIME_COLUMNS)}
	metricsName := ""
	table := ""
	// get metrics_name and all filter columns from query statement
	isShowTagStatement := false
	if st, ok := ctx.Value(CtxKeyShowTag{}).(bool); ok {
		isShowTagStatement = st
	}
	ctx = context.WithValue(ctx, ctxKeyPrefixType{}, prefixNone)

	// get metrics_name from the query
	for _, matcher := range q.Matchers {
		if matcher.Name == PROMETHEUS_METRICS_NAME {
			metricsName = matcher.Value
			if strings.Contains(metricsName, "__") {
				// DeepFlow native metrics: ${db}__${table}__${metricsName}
				// i.e.: flow_log__l4_flow_log__byte_rx
				// DeepFlow native metrics(flow_metrics): ${db}__${table}__${metricsName}__${datasource}
				// i.e.: flow_metrics__vtap_flow_port__byte_rx__1m
				// Prometheus/InfluxDB integrated metrics: ext_metrics__metrics__${integratedSource}_${metricsName}
				// i.e.: ext_metrics__metrics__prometheus_node_cpu_seconds_total
				metricsSplit := strings.Split(metricsName, "__")
				if _, ok := chCommon.DB_TABLE_MAP[metricsSplit[0]]; ok {
					db = metricsSplit[0]
					table = metricsSplit[1] // FIXME: should fix deepflow_system table name like 'deepflow_server.xxx'
					metricsName = metricsSplit[2]

					if db == DB_NAME_DEEPFLOW_SYSTEM {
						metrics = append(metrics, fmt.Sprintf("metrics.%s", metricsName))
					} else if db == DB_NAME_EXT_METRICS {
						// identify tag prefix as "tag_"
						ctx = context.WithValue(ctx, ctxKeyPrefixType{}, prefixTag)

						// convert prometheus_xx/influxdb_xx to prometheus.xxx/influxdb.xx (split to 2 parts)
						realMetrics := strings.SplitN(metricsName, "_", 2)
						if len(realMetrics) > 1 {
							table = fmt.Sprintf("%s.%s", realMetrics[0], realMetrics[1])
							metricsName = realMetrics[1]
						}
						metrics = append(metrics, fmt.Sprintf("metrics.%s", metricsName))
					} else {
						// To identify which columns belong to metrics, we prefix all metrics names with `metrics.`
						metrics = append(metrics, fmt.Sprintf("%s as `metrics.%s`", metricsName, metricsName))
					}

					if len(metricsSplit) > 3 {
						datasource = metricsSplit[3]
					}
				} else {
					return ctx, "", "", "", fmt.Errorf("unknown metrics %v", metricsName)
				}
			} else {
				// Prometheus native metrics: ${metricsName}
				// identify prefix for tag names with "df_"
				ctx = context.WithValue(ctx, ctxKeyPrefixType{}, prefixDeepFlow)
				metrics = append(metrics, fmt.Sprintf("metrics.%s", metricsName))
			}
			break
		}
	}

	if len(metrics) == 1 {
		return ctx, "", "", "", errors.New("not support find metrics with labels")
	}

	// get all available tag names for the metrics, when the query is a ShowTag statement
	if isShowTagStatement {
		showTags := "SHOW tags FROM %s.%s WHERE time >= %d AND time <= %d"
		var data *common.Result
		if db == "" || db == chCommon.DB_NAME_EXT_METRICS {
			data, err = tagdescription.GetTagDescriptions(chCommon.DB_NAME_EXT_METRICS, EXT_METRICS_TABLE, fmt.Sprintf(showTags, chCommon.DB_NAME_EXT_METRICS, EXT_METRICS_TABLE, startTime, endTime), context.TODO())
		} else {
			data, err = tagdescription.GetTagDescriptions(db, table, fmt.Sprintf(showTags, db, table, startTime, endTime), context.TODO())
		}
		if err != nil {
			return ctx, "", "", "", err
		}

		for _, value := range data.Values {
			// data.Columns definitions:
			// "columns": ["name","client_name","server_name","display_name","type","category","operators","permissions","description","related_tag"]
			// i.e.: columns[i] defines name of values[i]
			values := value.([]interface{})
			tagName := values[0].(string)
			if common.IsValueInSliceString(tagName, ignorableTagNames) {
				continue
			}
			clientTagName := values[1].(string)
			serverTagName := values[2].(string)
			tagType := values[4].(string)
			if tagType == IGNORABLE_TAG_TYPE && tagName != EXT_METRICS_NATIVE_TAG_NAME {
				continue
			}

			// `edgeTable` storage data which contains both client and server-side, so metrics should cover both, else only one of them
			// e.g.: auto_instance_0/auto_instance_1 in `vtap_app_edge_port`, auto_instance in `vtap_app_port`
			if common.IsValueInSliceString(table, edgeTableNames) && tagName != clientTagName {
				metrics = append(metrics, fmt.Sprintf("`%s`", clientTagName))
				metrics = append(metrics, fmt.Sprintf("`%s`", serverTagName))
			} else {
				metrics = append(metrics, fmt.Sprintf("`%s`", tagName))
			}
		}
	} else if db == "" || db == chCommon.DB_NAME_EXT_METRICS || db == chCommon.DB_NAME_DEEPFLOW_SYSTEM {
		// append ext_metrics native tag
		metrics = append(metrics, EXT_METRICS_NATIVE_TAG_NAME)
	} else if db == chCommon.DB_NAME_FLOW_METRICS {
		if table == VTAP_APP_PORT_TABLE || table == VTAP_FLOW_PORT_TABLE {
			// append native tag
			metrics = append(metrics, AUTO_INSTANCE_TAG_NAME)
		} else if table == VTAP_APP_EDGE_PORT_TABLE || table == VTAP_FLOW_EDGE_PORT_TABLE {
			// append native tag & capture info
			metrics = append(metrics, fmt.Sprintf("`%s_0`", AUTO_INSTANCE_TAG_NAME)) // client side tag
			metrics = append(metrics, fmt.Sprintf("`%s_1`", AUTO_INSTANCE_TAG_NAME)) // server side tag
			metrics = append(metrics, TAP_SIDE_TAG_NAME)                             // capture info tag
		}
	} else {
		// do nothing
		// not supported for other db/tables currently
	}

	// filters
	for _, matcher := range q.Matchers {
		if matcher.Name == PROMETHEUS_METRICS_NAME {
			continue
		}

		operation := getLabelMatcherType(matcher.Type)
		if operation == "" {
			return ctx, "", "", "", fmt.Errorf("unknown match type %v", matcher.Type)
		}

		switch db {
		case "", chCommon.DB_NAME_DEEPFLOW_SYSTEM:
			if strings.HasPrefix(matcher.Name, config.Cfg.Prometheus.AutoTaggingPrefix) {
				tagName := convertToQuerierAllowedTagName(removeDeepFlowPrefix(matcher.Name))
				filters = append(filters, fmt.Sprintf("`%s` %s '%s'", tagName, operation, matcher.Value))
				// when PromQL mention a deepflow universal tag, append into metrics
				metrics = append(metrics, tagName)
			} else {
				filters = append(filters, fmt.Sprintf("`tag.%s` %s '%s'", matcher.Name, operation, matcher.Value))
			}
		default:
			// deepflow metrics (vtap_app/flow_part/edge_part & ext_metrics)
			if strings.HasPrefix(matcher.Name, "tag_") {
				filters = append(filters, fmt.Sprintf("`tag.%s` %s '%s'", removeTagPrefix(matcher.Name), operation, matcher.Value))
			} else {
				// convert k8s label tag to query tag
				tagName := convertToQuerierAllowedTagName(matcher.Name)
				filters = append(filters, fmt.Sprintf("`%s` %s '%s'", tagName, operation, matcher.Value))

				// append quering tags, but ignore auto_instance_x/tap_side / tag_
				if !strings.HasPrefix(tagName, AUTO_INSTANCE_TAG_NAME) && tagName != TAP_SIDE_TAG_NAME {
					metrics = append(metrics, tagName)
				}
			}
		}
	}

	// order by DESC for get data completely, then scan data reversely for data combine(see func.RespTransToProm)
	// querier will be called later, so there is no need to display the declaration db
	if db != "" {
		// FIXME: if db is ext_metrics, only support for prometheus metrics now
		sql = fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY time desc LIMIT %s",
			strings.Join(metrics, ","), table, strings.Join(filters, " AND "), config.Cfg.Limit)
	} else {
		sql = fmt.Sprintf("SELECT %s FROM prometheus.%s WHERE %s ORDER BY time desc LIMIT %s",
			strings.Join(metrics, ","), metricsName, strings.Join(filters, " AND "), config.Cfg.Limit)
	}
	return ctx, sql, db, datasource, nil
}

// querier result trans to Prom Response
func RespTransToProm(ctx context.Context, result *common.Result) (resp *prompb.ReadResponse, err error) {
	tagIndex := -1
	metricsIndex := -1
	timeIndex := -1
	otherTagCount := 0
	metricsName := ""
	prefix, _ := ctx.Value(ctxKeyPrefixType{}).(prefix) // ignore if key not exist
	for i, tag := range result.Columns {
		if tag == EXT_METRICS_NATIVE_TAG_NAME {
			tagIndex = i
		} else if strings.HasPrefix(tag.(string), "metrics.") {
			metricsIndex = i
			metricsName = strings.TrimPrefix(tag.(string), "metrics.")
		} else if tag == EXT_METRICS_TIME_COLUMNS {
			timeIndex = i
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
		if i == tagIndex || i == metricsIndex || i == timeIndex {
			continue
		}
		allDeepFlowNativeTags = append(allDeepFlowNativeTags, i)
	}

	// Scan all the results, determine the seriesID of each sample and the number of samples in each series,
	// so that the size of the sample array in each series can be determined in advance.
	maxPossibleSeries := len(result.Values)
	if maxPossibleSeries > config.Cfg.Prometheus.SeriesLimit {
		maxPossibleSeries = config.Cfg.Prometheus.SeriesLimit
	}

	seriesIndexMap := map[string]int32{}                            // the index in seriesArray, for each `tagsJsonStr`
	seriesArray := make([]*prompb.TimeSeries, 0, maxPossibleSeries) // series storage
	sampleSeriesIndex := make([]int32, len(result.Values))          // the index in seriesArray, for each sample
	seriesSampleCount := make([]int32, maxPossibleSeries)           // number of samples of each series
	initialSeriesIndex := int32(0)

	tagsStrList := make([]string, 0, len(allDeepFlowNativeTags))
	for i, v := range result.Values {
		values := v.([]interface{})

		// merge and serialize all tags as map key
		var deepflowNativeTagString, promTagJson string
		// merge prometheus tags
		if tagIndex > -1 {
			promTagJson = values[tagIndex].(string)
			deepflowNativeTagString = promTagJson
		}

		// merge deepflow autotagging tags
		if len(allDeepFlowNativeTags) > 0 {
			for _, idx := range allDeepFlowNativeTags {
				tagsStrList = append(tagsStrList, strconv.Itoa(idx))
				tagsStrList = append(tagsStrList, getValue(values[idx]))
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
			if len(seriesIndexMap) >= config.Cfg.Prometheus.SeriesLimit {
				sampleSeriesIndex[i] = -1
				continue
			}

			// tag label pair
			var pairs []prompb.Label
			if tagIndex > -1 {
				tagMap := make(map[string]string)
				json.Unmarshal([]byte(promTagJson), &tagMap)
				pairs = make([]prompb.Label, 0, 1+len(tagMap)+len(allDeepFlowNativeTags))
				if prefix == prefixTag {
					// prometheus tag for deepflow metrics
					for k, v := range tagMap {
						pairs = append(pairs, prompb.Label{
							Name:  appendPrometheusPrefix(k),
							Value: v,
						})
					}
				} else {
					// no prefix, use prometheus native tag
					for k, v := range tagMap {
						pairs = append(pairs, prompb.Label{
							Name:  k,
							Value: v,
						})
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
				if tagIndex > -1 && prefix == prefixDeepFlow {
					// deepflow tag for prometheus metrics
					pairs = append(pairs, prompb.Label{
						Name:  appendDeepFlowPrefix(formatTagName(result.Columns[idx].(string))),
						Value: getValue(values[idx]),
					})
				} else {
					pairs = append(pairs, prompb.Label{
						Name:  formatTagName(result.Columns[idx].(string)),
						Value: getValue(values[idx]),
					})
				}
			}

			// append the special tag: "__name__": "$metricsName"
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
		var metricsValue float64
		if metricsType == "Int" {
			metricsValue = float64(values[metricsIndex].(int))
		} else if metricsType == "Float64" {
			metricsValue = values[metricsIndex].(float64)
		} else {
			return nil, errors.New(fmt.Sprintf("Unknown metrics type %s, value = %v", metricsType, values[metricsIndex]))
		}

		// add a sample for the TimeSeries
		seriesIndex := sampleSeriesIndex[i]
		series := seriesArray[seriesIndex]
		if cap(series.Samples) == 0 {
			series.Samples = make([]prompb.Sample, 0, seriesSampleCount[seriesIndex])
		}
		series.Samples = append(
			series.Samples, prompb.Sample{
				Timestamp: int64(values[timeIndex].(int)) * 1000,
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

// match prometheus lable matcher type
func getLabelMatcherType(t prompb.LabelMatcher_Type) string {
	switch t {
	case prompb.LabelMatcher_EQ:
		return "="
	case prompb.LabelMatcher_NEQ:
		return "!="
	case prompb.LabelMatcher_RE:
		return "REGEXP"
	case prompb.LabelMatcher_NRE:
		return "NOT REGEXP"
	default:
		return ""
	}
}

func getValue(value interface{}) string {
	switch val := value.(type) {
	case int:
		return strconv.Itoa(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case time.Time:
		return val.String()
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
	default:
		return false
	}
}

func formatTagName(tagName string) (newTagName string) {
	newTagName = strings.ReplaceAll(tagName, ".", "_")
	newTagName = strings.ReplaceAll(newTagName, "-", "_")
	newTagName = strings.ReplaceAll(newTagName, "/", "_")
	return newTagName
}

func appendDeepFlowPrefix(tag string) string {
	return fmt.Sprintf("%s%s", config.Cfg.Prometheus.AutoTaggingPrefix, tag)
}

func appendPrometheusPrefix(tag string) string {
	return fmt.Sprintf("tag_%s", tag)
}

// FIXME: should reverse `formatTagName` funtion, build a `tag` map during series query
func convertToQuerierAllowedTagName(matcherName string) (tagName string) {
	tagName = matcherName
	for k, v := range matcherRules {
		if strings.HasPrefix(tagName, k) {
			tagName = strings.Replace(tagName, k, v, 1)
			return tagName
		}
	}
	return tagName
}

func removeDeepFlowPrefix(tag string) string {
	return strings.TrimPrefix(tag, config.Cfg.Prometheus.AutoTaggingPrefix)
}

func removeTagPrefix(tag string) string {
	return strings.Replace(tag, "tag_", "", 1)
}
