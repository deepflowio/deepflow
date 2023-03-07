package prometheus

import (
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
	prometheusMetricsName = "__name__"
	extMetricsTagsName    = "tag"
	extMetricsTimeAlias   = "timestamp"
)

var EDGE_TABLE_NAMES = []string{
	"vtap_flow_edge_port", "vtap_app_edge_port", "l4_flow_log", "l7_flow_log",
}

func PromReaderTransToSQL(req *prompb.ReadRequest) (sql string, db string, datasource string, err error) {
	queriers := req.Queries
	if len(queriers) < 1 {
		// TODO
		return "", "", "", errors.New("len(req.Queries) == 0, this feature is not yet implemented!")
	}
	q := queriers[0]
	//pp.Println(q)

	startTime := q.Hints.StartMs / 1000
	endTime := q.Hints.EndMs / 1000
	if q.EndTimestampMs%1000 > 0 {
		endTime += 1
	}
	timeFilter := fmt.Sprintf("(time >= %d AND time <= %d)", startTime, endTime)
	filters := []string{timeFilter}
	metrics := []string{fmt.Sprintf("toUnixTimestamp(time) AS %s", extMetricsTimeAlias)}
	metricsName := ""
	table := ""

	// metrics_name
	for _, matcher := range q.Matchers {
		if matcher.Name == prometheusMetricsName {
			metricsName = matcher.Value
			if strings.Contains(metricsName, "__") {
				// DeepFlow native metrics: ${db}__${table}__${metricsName}
				// Prometheus/InfluxDB integrated metrics: ext_metrics__ext_common__${metricsName}
				metricsSplit := strings.Split(metricsName, "__")
				if _, ok := chCommon.DB_TABLE_MAP[metricsSplit[0]]; ok {
					db = metricsSplit[0]
					table = metricsSplit[1]
					metricsName = metricsSplit[2]
					// To identify which columns belong to metrics, we prefix all metrics names with `metrics.`
					metrics = append(metrics, fmt.Sprintf("%s as `metrics.%s`", metricsName, metricsName))
					if len(metricsSplit) > 3 {
						datasource = metricsSplit[3]
					}
				} else {
					return "", "", "", fmt.Errorf("unknown metrics %v", metricsName)
				}
			} else {
				// Prometheus integrated metrics: ${metricsName}
				metrics = append(metrics, fmt.Sprintf("metrics.%s", metricsName))
			}
			break
		}
	}

	// filter
	for _, matcher := range q.Matchers {
		if matcher.Name == prometheusMetricsName {
			continue
		}

		op := ""
		switch matcher.Type {
		case prompb.LabelMatcher_EQ:
			op = "="
		case prompb.LabelMatcher_NEQ:
			op = "!="
		case prompb.LabelMatcher_RE:
			op = "regexp"
		case prompb.LabelMatcher_NRE:
			op = "not regexp"
		default:
			return "", "", "", fmt.Errorf("unknown match type %v", matcher.Type)
		}

		if db != "" && db != chCommon.DB_NAME_EXT_METRICS && db != chCommon.DB_NAME_DEEPFLOW_SYSTEM {
			filters = append(filters, fmt.Sprintf("%s %s '%s'", matcher.Name, op, matcher.Value))
		} else {
			filters = append(filters, fmt.Sprintf("`tag.%s` %s '%s'", matcher.Name, op, matcher.Value))
		}
	}

	if len(metrics) == 1 {
		return "", "", "", fmt.Errorf("not support find metrics with labels")
	}

	if db == "" || db == chCommon.DB_NAME_EXT_METRICS || db == chCommon.DB_NAME_DEEPFLOW_SYSTEM {
		metrics = append(metrics, extMetricsTagsName)
	} else {
		showSql := fmt.Sprintf("SHOW tags FROM %s WHERE time >= %d AND time <= %d", table, startTime, endTime)
		data, _ := tagdescription.GetTagDescriptions(db, table, showSql, nil)
		for _, value := range data.Values {
			values := value.([]interface{})
			tagName := values[0].(string)
			if tagName == "lb_listener" || tagName == "pod_ingress" { // TODO: why? comment
				continue
			}
			clientTagName := values[1].(string)
			serverTagName := values[2].(string)
			if common.IsValueInSliceString(table, EDGE_TABLE_NAMES) && tagName != clientTagName {
				metrics = append(metrics, fmt.Sprintf("`%s`", clientTagName))
				metrics = append(metrics, fmt.Sprintf("`%s`", serverTagName))
			} else {
				metrics = append(metrics, fmt.Sprintf("`%s`", tagName))
			}
		}
	}

	// order by DESC for get data completely, then scan data reversely for data combine(see func.RespTransToProm)
	if db != "" {
		sql = fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY time desc LIMIT %s",
			strings.Join(metrics, ","), table, strings.Join(filters, " AND "), config.Cfg.Limit)
	} else {
		sql = fmt.Sprintf("SELECT %s FROM prometheus.%s WHERE %s ORDER BY time desc LIMIT %s",
			strings.Join(metrics, ","), metricsName, strings.Join(filters, " AND "), config.Cfg.Limit)
	}
	return sql, db, datasource, nil
}

// querier result trans to Prom Response
func RespTransToProm(result *common.Result) (resp *prompb.ReadResponse, err error) {
	tagIndex := -1
	metricsIndex := -1
	timeIndex := -1
	otherTagCount := 0
	metricsName := ""
	for i, tag := range result.Columns {
		if tag == extMetricsTagsName {
			tagIndex = i
		} else if strings.HasPrefix(tag.(string), "metrics.") {
			metricsIndex = i
			metricsName = strings.TrimPrefix(tag.(string), "metrics.")
		} else if tag == extMetricsTimeAlias {
			timeIndex = i
		} else {
			otherTagCount++
		}
	}
	if metricsIndex < 0 || timeIndex < 0 {
		return nil, fmt.Errorf("metricsIndex(%d), timeIndex(%d) get failed", metricsIndex, timeIndex)
	}
	metricsType := result.Schemas[metricsIndex].ValueType

	// ext_metrics & deepflow_system dont have other tags, flow_metrics & flow_log dont have `tag`
	allTagIndexs := make([]int, 0, otherTagCount)
	for i := range result.Columns {
		if i == tagIndex || i == metricsIndex || i == timeIndex {
			continue
		}
		allTagIndexs = append(allTagIndexs, i)
	}

	// Scan all the results, determine the seriesID of each sample and the number of samples in each series,
	// so that the size of the sample array in each series can be determined in advance.
	maxPossibleSeries := len(result.Values)
	if maxPossibleSeries > config.Cfg.Prometheus.SeriesLimit {
		maxPossibleSeries = config.Cfg.Prometheus.SeriesLimit
	}
	seriesIndexMap := map[string]int32{} // the index in seriesArray, for each `tagsJsonStr`
	seriesArray := make([]*prompb.TimeSeries, 0, maxPossibleSeries)
	sampleSeriesIndex := make([]int32, len(result.Values)) // the index in seriesArray, for each sample
	seriesSampleCount := make([]int32, maxPossibleSeries)  // number of samples of each series
	initialSeriesIndex := int32(0)
	for i, v := range result.Values {
		values := v.([]interface{})

		// merge and serialize all tags as map key
		tagsJsonStr := ""
		if tagIndex > -1 {
			tagsJsonStr = values[tagIndex].(string)
		} else {
			tagsStrList := make([]string, 0, len(allTagIndexs))
			for _, idx := range allTagIndexs {
				// remove nil tag
				if ValueIsNil(values[idx]) {
					continue
				}
				tagsStrList = append(tagsStrList, strconv.Itoa(idx))
				tagsStrList = append(tagsStrList, FormatString(values[idx]))
			}
			tagsJsonStr = strings.Join(tagsStrList, "-")
		}

		// check and assign seriesIndex
		var series *prompb.TimeSeries
		index, exist := seriesIndexMap[tagsJsonStr]
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
				json.Unmarshal([]byte(tagsJsonStr), &tagMap)
				pairs = make([]prompb.Label, 0, 1+len(tagMap))
				for k, v := range tagMap {
					pairs = append(pairs, prompb.Label{
						Name:  k,
						Value: v,
					})
				}
			} else {
				pairs = make([]prompb.Label, 0, 1+len(allTagIndexs))
				for _, idx := range allTagIndexs {
					// remove nil tag
					if ValueIsNil(values[idx]) {
						continue
					}
					pairs = append(pairs, prompb.Label{
						Name:  FromatTagName(result.Columns[idx].(string)),
						Value: FormatString(values[idx]),
					})
				}
			}
			// append the special tag: "__name__": "$metricsName"
			pairs = append(pairs, prompb.Label{
				Name:  prometheusMetricsName,
				Value: metricsName,
			})

			series = &prompb.TimeSeries{
				Labels: pairs,
			}

			seriesIndexMap[tagsJsonStr] = initialSeriesIndex
			seriesArray = append(seriesArray, series)
			sampleSeriesIndex[i] = index
			seriesSampleCount[index] = 1
			initialSeriesIndex++
		}
	}

	// reverse scan, make data order by time asc for prometheus filter handling (happens in prometheus promql engine)
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
			metricsValue = *values[metricsIndex].(*float64)
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
	resp.Results[0].Timeseries = make([]*prompb.TimeSeries, 0, len(seriesArray))
	for _, series := range seriesArray {
		resp.Results[0].Timeseries = append(resp.Results[0].Timeseries, series)
	}
	return resp, nil
}

func FormatString(a interface{}) string {
	switch a := a.(type) {
	case int:
		return strconv.Itoa(a)
	case float64:
		return strconv.FormatFloat(a, 'f', -1, 64)
	case time.Time:
		return a.String()
	default:
		return a.(string)
	}
	return a.(string)
}

func ValueIsNil(a interface{}) bool {
	switch a := a.(type) {
	case string:
		return a == "" || a == "{}"
	case int:
		return a == 0
	default:
		return false
	}
	return false
}

func FromatTagName(tagName string) (newTagName string) {
	newTagName = strings.ReplaceAll(tagName, ".", "_")
	newTagName = strings.ReplaceAll(newTagName, "-", "_")
	newTagName = strings.ReplaceAll(newTagName, "/", "_")
	return newTagName
}
