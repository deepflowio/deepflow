package prometheus

import (
	"encoding/json"
	"fmt"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/prometheus/prometheus/prompb"
	"strings"
)

const (
	prometheusMetricsName = "__name__"
	extMetricsTagsName    = "tags"
	extMetricsTimeAlias   = "timestamp"
)

func PromReaderTransToSQL(req *prompb.ReadRequest) (sql string, err error) {
	queriers := req.Queries
	if len(queriers) < 1 {
		// TODO
		return "", nil
	}
	q := queriers[0]
	startTime := q.StartTimestampMs / 1000
	endTime := q.EndTimestampMs / 1000
	if q.EndTimestampMs%1000 > 0 {
		endTime += 1
	}
	timeFilter := fmt.Sprintf("(time >= %d AND time <= %d)", startTime, endTime)
	filters := []string{timeFilter}
	metrics := []string{extMetricsTagsName, fmt.Sprintf("toUnixTimestamp(time) AS %s", extMetricsTimeAlias)}
	metircsName := ""
	// filter
	for _, matcher := range q.Matchers {
		// __name__为metrics
		if matcher.Name == prometheusMetricsName {
			metircsName = matcher.Value
			metrics = append(metrics, fmt.Sprintf("metrics.%s", metircsName))
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
			return "", fmt.Errorf("unknown match type %v", matcher.Type)
		}
		filters = append(filters, fmt.Sprintf("`tag.%s`%s'%s'", matcher.Name, op, matcher.Value))
	}
	sql = fmt.Sprintf("SELECT %s FROM prometheus.%s WHERE %s", strings.Join(metrics, ","), metircsName, strings.Join(filters, " AND "))
	return sql, nil
}

func RespTransToProm(result *common.Result) (resp *prompb.ReadResponse, err error) {
	resp = &prompb.ReadResponse{
		Results: []*prompb.QueryResult{{}},
	}
	tags := result.Columns
	tagIndex := -1
	metricsIndex := -1
	timeIndex := -1
	metricsName := ""
	for i, tag := range tags {
		if tag == extMetricsTagsName {
			tagIndex = i
		} else if strings.HasPrefix(tag.(string), "metrics.") {
			metricsIndex = i
			metricsName = strings.TrimPrefix(tag.(string), "metrics.")
		} else if tag == extMetricsTimeAlias {
			timeIndex = i
		}
	}
	if tagIndex < 0 || metricsIndex < 0 || timeIndex < 0 {
		return nil, fmt.Errorf("tagIndex(%d), metricsIndex(%d), timeIndex(%d) get failed", tagIndex, metricsIndex, timeIndex)
	}
	tagSeriesMap := map[string]*prompb.TimeSeries{}
	for _, v := range result.Values {
		values := v.([]interface{})
		tagsJsonStr := values[tagIndex].(string)
		if _, ok := tagSeriesMap[tagsJsonStr]; !ok {
			// __name__:metricsName
			pairs := []prompb.Label{prompb.Label{
				Name:  prometheusMetricsName,
				Value: metricsName,
			}}
			// tag label pair
			pairs = append(pairs, TagsToLabelPairs(tagsJsonStr)...)
			series := &prompb.TimeSeries{
				Labels: pairs,
			}
			tagSeriesMap[tagsJsonStr] = series
		}
		// group by tags
		tagSeriesMap[tagsJsonStr].Samples = append(
			tagSeriesMap[tagsJsonStr].Samples, prompb.Sample{
				Timestamp: int64(values[timeIndex].(int)) * 1000,
				Value:     *values[metricsIndex].(*float64),
			},
		)

	}
	for _, series := range tagSeriesMap {
		resp.Results[0].Timeseries = append(resp.Results[0].Timeseries, series)
	}
	return resp, nil
}

func TagsToLabelPairs(tagsJsonStr string) []prompb.Label {
	pairs := []prompb.Label{}
	m := make(map[string]string)
	json.Unmarshal([]byte(tagsJsonStr), &m)
	for k, v := range m {
		pairs = append(pairs, prompb.Label{
			Name:  string(k),
			Value: v,
		})
	}
	return pairs
}
