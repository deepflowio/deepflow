package prometheus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/server/querier/common"
	//"github.com/k0kubun/pp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
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

// API Spec: https://prometheus.io/docs/prometheus/latest/querying/api/#instant-queries
func PromQueryExecute(args *common.PromQueryParams, ctx context.Context) (result *common.PromQueryResponse, err error) {
	timeS, err := (strconv.ParseFloat(args.StartTime, 64))
	if err != nil {
		return nil, err
	}
	//timeMs := int64(timeS * 1000)
	opts := promql.EngineOpts{
		Logger:                   nil,
		Reg:                      nil,
		MaxSamples:               100000,
		Timeout:                  100 * time.Second,
		NoStepSubqueryIntervalFn: func(int64) int64 { return durationMilliseconds(1 * time.Minute) },
		EnableAtModifier:         true,
		EnableNegativeOffset:     true,
		EnablePerStepStats:       true,
	}
	e := promql.NewEngine(opts)
	//pp.Println(opts.MaxSamples)
	qry, err := e.NewInstantQuery(&RemoteReadQuerierable{Args: args, Ctx: ctx}, nil, args.Promql, time.Unix(int64(timeS), 0))
	if qry == nil || err != nil {
		//pp.Println(err)
		log.Error(err)
		return nil, err
	}
	res := qry.Exec(ctx)
	//pp.Println(res.Err)
	//pp.Println(res)
	//pp.Println(res.Value.(promql.Vector))
	var resultType parser.ValueType
	if res.Value == nil {
		resultType = parser.ValueTypeNone
	} else {
		resultType = res.Value.Type()
	}
	return &common.PromQueryResponse{
		Data: &common.PromQueryData{
			ResultType: resultType,
			Result:     res.Value,
		}, Status: _SUCCESS}, err
}

func durationMilliseconds(d time.Duration) int64 {
	return int64(d / (time.Millisecond / time.Nanosecond))
}

func PromQueryRangeExecute(args *common.PromQueryParams, ctx context.Context) (result *common.PromQueryResponse, err error) {
	startS, err := (strconv.ParseFloat(args.StartTime, 64))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	endS, err := (strconv.ParseFloat(args.EndTime, 64))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	step, err := (parseDuration(args.Step))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	//timeMs := int64(timeS * 1000)
	opts := promql.EngineOpts{
		Logger:                   nil,
		Reg:                      nil,
		MaxSamples:               100000,
		Timeout:                  100 * time.Second,
		NoStepSubqueryIntervalFn: func(int64) int64 { return durationMilliseconds(1 * time.Minute) },
		EnableAtModifier:         true,
		EnableNegativeOffset:     true,
		EnablePerStepStats:       true,
	}
	e := promql.NewEngine(opts)
	//pp.Println(opts.MaxSamples)
	qry, err := e.NewRangeQuery(&RemoteReadRangeQuerierable{Args: args, Ctx: ctx}, nil, args.Promql, time.Unix(int64(startS), 0), time.Unix(int64(endS), 0), step)
	if qry == nil || err != nil {
		log.Error(err)
		return nil, err
	}
	res := qry.Exec(ctx)
	//pp.Println(res.Value.(promql.Matrix))
	//pp.Println(res.Err)
	//pp.Println(res)
	var resultType parser.ValueType
	if res.Value == nil {
		resultType = parser.ValueTypeNone
	} else {
		resultType = res.Value.Type()
	}
	return &common.PromQueryResponse{
		Data: &common.PromQueryData{
			ResultType: resultType,
			Result:     res.Value,
		}, Status: _SUCCESS}, err
}

func parseDuration(s string) (time.Duration, error) {
	if d, err := strconv.ParseFloat(s, 64); err == nil {
		ts := d * float64(time.Second)
		if ts > float64(math.MaxInt64) || ts < float64(math.MinInt64) {
			return 0, fmt.Errorf("cannot parse %q to a valid duration. It overflows int64", s)
		}
		return time.Duration(ts), nil
	}
	if d, err := model.ParseDuration(s); err == nil {
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
// TODO: 可以先不要返回 flow_metrics 以外的数据？并检查 deepflow_system 是否支持 promQL
func Series(args *common.PromQueryParams) (result *common.PromQueryResponse, err error) {
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

	labelMatchers, err := parseMatchersParam(args.Matchers)
	// pp.Println(args.Matchers)
	// pp.Println(matcherSets)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	querierable := &RemoteReadQuerierable{Args: args, Ctx: args.Context}
	q, err := querierable.Querier(args.Context, timestamp.FromTime(start), timestamp.FromTime(end))
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

	return &common.PromQueryResponse{Data: metrics, Status: _SUCCESS}, err
}
