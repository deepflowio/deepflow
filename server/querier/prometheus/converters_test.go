package prometheus

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/prometheus/prometheus/prompb"
	. "github.com/smartystreets/goconvey/convey"
)

type promqlParse struct {
	input  string
	output string
	db     string
	ds     string

	hints    promqlHints
	hasError bool
}

type promqlHints struct {
	matcher  string
	stepMs   int64
	aggOp    string
	grouping []string
	by       bool
	// rangeMs  int64
}

func TestMain(m *testing.M) {
	// init runtime objects for tests
	QPSLeakyBucket = new(datastructure.LeakyBucket)
	QPSLeakyBucket.Init(1e9)

	config.Cfg = &config.QuerierConfig{Limit: "10000"}

	// run for test
	m.Run()
}

func TestPromReaderTransToSQL(t *testing.T) {
	endMs := time.Now().UnixMicro()
	startMs := endMs - 5*60*1e3 // minus 5mins
	endS := endMs / 1e3
	startS := startMs / 1e3
	if endS%1000 > 0 {
		endS += 1
	}

	limit := config.Cfg.Limit

	promqls := []promqlParse{
		{
			hints:    promqlHints{matcher: "flow_metrics__vtap_flow_port__rtt_max__1m"},
			input:    "flow_metrics__vtap_flow_port__rtt_max__1m",
			hasError: true,
		},
		{
			hints:    promqlHints{matcher: "flow_metrics__vtap_flow_port__rtt_max__1m"},
			input:    "stddev(flow_metrics__vtap_flow_port__rtt_max__1m)",
			hasError: true,
		},
		{
			hints:    promqlHints{matcher: "flow_metrics__vtap_flow_port__rtt_max__1m"},
			input:    "topk(flow_metrics__vtap_flow_port__rtt_max__1m)",
			hasError: true,
		},
		{
			hints:    promqlHints{matcher: "flow_metrics__vtap_flow_port__rtt_max__1m"},
			input:    "sum(flow_metrics__vtap_flow_port__rtt_max__1m)",
			hasError: true,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "sum", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_flow_port__rtt_max__1m", by: false},
			input:    "sum(flow_metrics__vtap_flow_port__rtt_max__1m)without(auto_instance)",
			hasError: true,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "sum", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_flow_port__rtt_max__1m", by: true},
			input:    "sum(flow_metrics__vtap_flow_port__rtt_max__1m)by(auto_instance)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance`,Sum(`rtt_max`) as `metrics.rtt_max` FROM vtap_flow_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1m",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "sum", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_flow_port__rtt_max__1s", by: true},
			input:    "sum by(auto_instance)(flow_metrics__vtap_flow_port__rtt_max__1s)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance`,Sum(`rtt_max`) as `metrics.rtt_max` FROM vtap_flow_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1s",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "sum", grouping: []string{"k8s_label_k8s_app"}, matcher: "flow_metrics__vtap_flow_port__rtt_max__1s", by: true},
			input:    "sum by(k8s_label_k8s_app)(flow_metrics__vtap_flow_port__rtt_max__1s)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`k8s.label.k8s_app`,Sum(`rtt_max`) as `metrics.rtt_max` FROM vtap_flow_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`k8s.label.k8s_app` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1s",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "avg", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_app_port__request__1m", by: true},
			input:    "avg(flow_metrics__vtap_app_port__request__1m) by(auto_instance)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance`,Avg(`request`) as `metrics.request` FROM vtap_app_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1m",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "count", grouping: []string{"auto_instance_0"}, matcher: "flow_log__l4_flow_log__rtt", by: true},
			input:    "count(flow_log__l4_flow_log__rtt) by(auto_instance_0)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_0`,Sum(`log_count`) as `metrics.rtt` FROM l4_flow_log WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_0` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "flow_log",
			hasError: false,
		},
		// flow_metrics don't support count
		{
			hints:    promqlHints{stepMs: 0, aggOp: "count", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_app_port__rrt__1m", by: true},
			input:    "count(flow_metrics__vtap_app_port__rrt__1m) by(auto_instance)",
			output:   "",
			ds:       "",
			db:       "",
			hasError: true,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "min", grouping: []string{"auto_instance_0"}, matcher: "flow_log__l4_flow_log__rtt", by: true},
			input:    "min by(auto_instance_0)(flow_log__l4_flow_log__rtt)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_0`,Min(`rtt`) as `metrics.rtt` FROM l4_flow_log WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_0` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "flow_log",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "max", grouping: []string{"auto_instance_1"}, matcher: "flow_log__l7_flow_log__log_count", by: true},
			input:    "max(flow_log__l7_flow_log__log_count) by(auto_instance_1)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_1`,Max(`log_count`) as `metrics.log_count` FROM l7_flow_log WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_1` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "flow_log",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "group", grouping: []string{"auto_instance_1"}, matcher: "flow_metrics__vtap_app_edge_port__request__1m", by: true},
			input:    "group(flow_metrics__vtap_app_edge_port__request__1m) by(auto_instance_1)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_1`,1 as `metrics.request` FROM vtap_app_edge_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_1` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1m",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "stddev", grouping: []string{"tap_side"}, matcher: "flow_metrics__vtap_app_edge_port__request__1s", by: true},
			input:    "stddev(flow_metrics__vtap_app_edge_port__request__1s) by(tap_side)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`tap_side`,Stddev(`request`) as `metrics.request` FROM vtap_app_edge_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`tap_side` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1s",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "count_values", grouping: []string{"auto_instance_0"}, matcher: "flow_log__l4_flow_log__rtt", by: true},
			input:    `count_values("service",flow_log__l4_flow_log__rtt)by(auto_instance_0)`,
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_0`,`rtt`,Sum(`log_count`) as `metrics.rtt` FROM l4_flow_log WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_0`,`rtt` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "flow_log",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "quantile", grouping: []string{"auto_instance_1"}, matcher: "flow_metrics__vtap_flow_edge_port__rtt_max__1s", by: true},
			input:    "quantile by(auto_instance_1)(0.5,flow_metrics__vtap_flow_edge_port__rtt_max__1s)",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,`auto_instance_1`,Percentile(`rtt_max`, 0) as `metrics.rtt_max` FROM vtap_flow_edge_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance_1` ORDER BY timestamp desc LIMIT %s", startS, endS, limit),
			ds:       "1s",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "", matcher: "demo_cpu_usage_seconds_total"},
			input:    "demo_cpu_usage_seconds_total",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,metrics.demo_cpu_usage_seconds_total,tag FROM prometheus.demo_cpu_usage_seconds_total WHERE (time >= %d AND time <= %d) ORDER BY time desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 0, aggOp: "", matcher: "demo_cpu_usage_seconds_total"},
			input:    "ext_metrics__metrics__prometheus_demo_cpu_usage_seconds_total",
			output:   fmt.Sprintf("SELECT toUnixTimestamp(time) AS timestamp,metrics.demo_cpu_usage_seconds_total,tag FROM prometheus.demo_cpu_usage_seconds_total WHERE (time >= %d AND time <= %d) ORDER BY time desc LIMIT %s", startS, endS, limit),
			ds:       "",
			db:       "",
			hasError: false,
		},

		// range query
		{
			hints:    promqlHints{stepMs: 10000, aggOp: "sum", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_flow_port__rtt_max__1m", by: true},
			input:    "sum(flow_metrics__vtap_flow_port__rtt_max__1m)by(auto_instance)",
			output:   fmt.Sprintf("SELECT time(time, %d) AS timestamp,`auto_instance`,Sum(`rtt_max`) as `metrics.rtt_max` FROM vtap_flow_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance` ORDER BY timestamp desc LIMIT %s", 10000/1000, startS, endS, limit),
			ds:       "1m",
			db:       "flow_metrics",
			hasError: false,
		},
		{
			hints:    promqlHints{stepMs: 10000, aggOp: "avg", grouping: []string{"auto_instance"}, matcher: "flow_metrics__vtap_app_port__request__1m", by: true},
			input:    "avg(flow_metrics__vtap_app_port__request__1m) by(auto_instance)",
			output:   fmt.Sprintf("SELECT time(time, %d) AS timestamp,`auto_instance`,Avg(`request`) as `metrics.request` FROM vtap_app_port WHERE (time >= %d AND time <= %d) GROUP BY timestamp,`auto_instance` ORDER BY timestamp desc LIMIT %s", 10000/1000, startS, endS, limit),
			ds:       "1m",
			db:       "flow_metrics",
			hasError: false,
		},
	}

	Convey("TestPromReaderTransToSQL_Query_Parse_1", t, func() {
		ctx := context.TODO()
		for _, p := range promqls {
			labelMatchers, err := parseMatchersParam([]string{p.hints.matcher})
			So(err, ShouldBeNil)

			queries := make([]*prompb.Query, 0, 1)
			matchers := make([]*prompb.LabelMatcher, 0, len(labelMatchers[0]))

			for _, l := range labelMatchers[0] {
				matchers = append(matchers, &prompb.LabelMatcher{
					Type:  prompb.LabelMatcher_Type(l.Type),
					Name:  l.Name,
					Value: l.Value,
				})
			}

			// instant query
			queries = append(queries, &prompb.Query{
				StartTimestampMs: endMs,
				EndTimestampMs:   endMs,
				Matchers:         matchers,
				Hints: &prompb.ReadHints{
					StepMs:   p.hints.stepMs,
					Func:     p.hints.aggOp,
					StartMs:  startMs, // when query instant, start=end-300s
					EndMs:    endMs,
					Grouping: p.hints.grouping,
					By:       p.hints.by, // false = without
				},
			})

			_, sql, db, ds, err := PromReaderTransToSQL(ctx, &prompb.ReadRequest{Queries: queries})

			if !p.hasError {
				So(err, ShouldBeNil)
			} else {
				So(err, ShouldNotBeNil)
			}

			So(sql, ShouldEqual, p.output)
			So(db, ShouldEqual, p.db)
			So(ds, ShouldEqual, p.ds)
			log.Info(sql)

		}
	})

}
