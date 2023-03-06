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
	stats := "success"
	var resultType parser.ValueType
	if res.Value == nil {
		resultType = parser.ValueTypeNone
	} else {
		resultType = res.Value.Type()
	}
	return &common.PromQueryResponse{Data: &common.PromQueryData{
		ResultType: resultType,
		Result:     res.Value,
	}, Status: stats}, err
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
	stats := "success"
	var resultType parser.ValueType
	if res.Value == nil {
		resultType = parser.ValueTypeNone
	} else {
		resultType = res.Value.Type()
	}
	return &common.PromQueryResponse{Data: &common.PromQueryData{
		ResultType: resultType,
		Result:     res.Value,
	}, Status: stats}, err
}

func parseDuration(s string) (time.Duration, error) {
	if d, err := strconv.ParseFloat(s, 64); err == nil {
		ts := d * float64(time.Second)
		if ts > float64(math.MaxInt64) || ts < float64(math.MinInt64) {
			return 0, errors.New(fmt.Sprintf("cannot parse %q to a valid duration. It overflows int64", s))
		}
		return time.Duration(ts), nil
	}
	if d, err := model.ParseDuration(s); err == nil {
		return time.Duration(d), nil
	}
	return 0, errors.New(fmt.Sprintf("cannot parse %q to a valid duration", s))
}

func parseMatchersParam(matchers []string) ([][]*labels.Matcher, error) {
	var matcherSets [][]*labels.Matcher
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

	return time.Time{}, errors.New(fmt.Sprintf("cannot parse %q to a valid timestamp", s))
}

// API Spec: https://prometheus.io/docs/prometheus/latest/querying/api/#finding-series-by-label-matchers
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

	matcherSets, err := parseMatchersParam(args.Matchers)
	//pp.Println(args.Matchers)
	//pp.Println(matcherSets)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	qable := &RemoteReadQuerierable{Args: args, Ctx: args.Context}
	q, err := qable.Querier(args.Context, timestamp.FromTime(start), timestamp.FromTime(end))

	if err != nil {
		log.Error(err)
		return nil, err
	}

	hints := &storage.SelectHints{
		Start: timestamp.FromTime(start),
		End:   timestamp.FromTime(end),
		Func:  "series", // There is no series function, this token is used for lookups that don't need samples.
	}
	var set storage.SeriesSet

	if len(matcherSets) > 1 {
		var sets []storage.SeriesSet
		for _, mset := range matcherSets {
			// We need to sort this select results to merge (deduplicate) the series sets later.
			s := q.Select(true, hints, mset...)
			sets = append(sets, s)
		}
		set = storage.NewMergeSeriesSet(sets, storage.ChainedSeriesMerge)
	} else {
		// At this point at least one match exists.
		set = q.Select(false, hints, matcherSets[0]...)
	}

	metrics := []labels.Labels{}
	for set.Next() {
		metrics = append(metrics, set.At().Labels())
	}

	if set.Err() != nil {
		log.Error(set.Err())
		return nil, set.Err()
	}

	stats := "success"
	return &common.PromQueryResponse{Data: metrics, Status: stats}, err
}
