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
	"math"
	"time"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
)

/*
 consider <VectorSelector> could only wrap by such expr:
 1. <Vector>  e.g.: node_cpu_seconds_total [output: <Vector>]
 2. Matrix<Vector>  e.g.: node_cpu_seconds_total[5m] [output: <Matrix>]
 3. SubQuery<Vector>  e.g.: node_cpu_seconds_total[5m:1m] [output: <Matrix>]
 4. Aggregate<Vector>  e.g.: sum(node_cpu_seconds_total)by(cpu) [input<Vector> output<Vector>]
 5. Call<Matrix>  e.g.: rate(node_cpu_seconds_total[5m]) [input<Matrix> output<Vector>]
 6. Call<Vector>  e.g.: abs(node_cpu_seconds_total) [input<Vector> output<Vector>]

 ...then, it can combined with each other,
 like: Call<SubQuery<Aggregate<Vector>>>
 e.g.: sum_over_time(sum(node_cpu_seconds_total)by(cpu)[5m:5m])
 e.g.: sum(sum_over_time(node_cpu_seconds_total[5m]))by(cpu)

 base on the combinations above, we could extract query hints by:
 - Call: get query func
 - MatrixSelector: get query range
 - AggregateExpr: get aggreagate function & aggregation group tags

 - Special: SubQueryExpr
 SubQueryExpr use a self-defined step for query (like: node_cpu_seconds_total[5m:1m]), [1m] is the step.
 When step > scrape_interval, it's downsampling, when step < scrape_interval, it's upsampling.

 parse case for wrap combinations:
 1&2. select value from m [where start < time < end];
 3. select last(value), time from m group by time;
 # upsampling:
 select time, sum(value) over (partition by metric_id,target_id,COLUMNS('app_label_value_id')
 order by time asc RANGE BETWEEN X PRECEDING AND CURRENT ROW) as `value`
 from m where start < time < end ORDER BY time WITH FILL STEP $STEP INTERPOLATE ( value AS value )
 4. select agg(value), time from m [where start < time < end] group by tags, time;
 - sum(node_cpu_seconds_total)by(cpu)[5m:1m]
 5. select time, call(value) over (partition by metric_id,target_id,COLUMNS('app_label_value_id')
 order by time asc RANGE BETWEEN X PRECEDING AND CURRENT ROW) from m where start < time < end;
 - x=[range * 60] (secs) (maybe it needs -1 secs for `x`), start = start - range (should calculate double time range for the first half of timestamp)
 6. select call(value) from m [where start < time < end];

 such exprs could only calculate by prometheus engine, ignore currently:
 BinaryExpr/UnaryExpr/ParenExpr/StepInvariantExpr/Others...
*/

type queryAnalyzer struct {
	lookBackDelta  time.Duration
	offloadEnabled offloadEnabledFunc
}

type functionCall struct {
	Range    time.Duration
	Param    float64       // only for `topk`/`bottomk`/`quantile`
	Name     string        // function name
	SubStep  time.Duration // for subQuery step in range query
	Grouping []string
}

// use QueryHint to get multiple `func` in promql query
type QueryHint struct {
	start    int64
	end      int64
	step     int64
	query    string
	funcs    []functionCall
	matchers []*labels.Matcher
}

func (q *QueryHint) GetStart() int64 {
	return q.start
}
func (q *QueryHint) GetEnd() int64 {
	return q.end
}

func (q *QueryHint) GetStep() int64 {
	return q.step
}

func (q *QueryHint) GetFunc() []string {
	f := make([]string, 0, len(q.funcs))
	for _, v := range q.funcs {
		f = append(f, v.Name)
	}
	return f
}

func (q *QueryHint) GetGrouping(f string) []string {
	for i := 0; i < len(q.funcs); i++ {
		if q.funcs[i].Name == f {
			return q.funcs[i].Grouping
		}
	}
	return nil
}

func (q *QueryHint) GetRange(f string) int64 {
	for i := 0; i < len(q.funcs); i++ {
		if q.funcs[i].Name == f {
			return int64(q.funcs[i].Range / (time.Millisecond / time.Nanosecond))
		}
	}
	return 0
}

func (q *QueryHint) GetSubStep(f string) int64 {
	for i := 0; i < len(q.funcs); i++ {
		if q.funcs[i].Name == f {
			return int64(q.funcs[i].SubStep / (time.Millisecond / time.Nanosecond))
		}
	}
	return 0
}

func (q *QueryHint) GetFuncParam(f string) float64 {
	// iterate from top to last
	for i := 0; i < len(q.funcs); i++ {
		if q.funcs[i].Name == f {
			return q.funcs[i].Param
		}
	}
	return 0
}

func (q *QueryHint) GetLabels() []*labels.Matcher {
	return q.matchers
}

func (q *QueryHint) GetQuery() string {
	return q.query
}

func (q *QueryHint) GetBy() bool {
	return true
}

func (q *QueryHint) GetMetric() string {
	return extractMetricName(&q.matchers)
}

// prometheusHint is for orginal prometheus SelectHints
type prometheusHint struct {
	hints    *storage.SelectHints
	matchers []*labels.Matcher
	query    string
}

func (p *prometheusHint) GetStart() int64 {
	return p.hints.Start
}
func (p *prometheusHint) GetEnd() int64 {
	return p.hints.End
}

func (p *prometheusHint) GetStep() int64 {
	return p.hints.Step
}

func (p *prometheusHint) GetFunc() []string {
	return []string{p.hints.Func}
}

func (p *prometheusHint) GetGrouping(f string) []string {
	// only one func
	if !p.hints.By {
		return nil
	}
	return p.hints.Grouping
}

func (p *prometheusHint) GetQuery() string {
	return p.query
}

func (p *prometheusHint) GetMetric() string {
	return extractMetricName(&p.matchers)
}

func (p *prometheusHint) GetRange(f string) int64 {
	return p.hints.Range
}

func (p *prometheusHint) GetLabels() []*labels.Matcher {
	return p.matchers
}

func (p *prometheusHint) GetBy() bool {
	return p.hints.By
}

// not implement
func (p *prometheusHint) GetFuncParam(f string) float64 {
	return 0
}

// not implement
func (q *prometheusHint) GetSubStep(f string) int64 {
	return 0
}

func newQueryAnalyzer(lookBackDelta time.Duration) *queryAnalyzer {
	return &queryAnalyzer{
		lookBackDelta:  lookBackDelta,
		offloadEnabled: offloadEnabled,
	}
}

func (d *queryAnalyzer) parsePromQL(qry string, start time.Time, end time.Time, interval time.Duration) []model.QueryRequest {
	// build Expr from promql analysis
	expr, err := parser.ParseExpr(qry)
	if err != nil {
		return nil
	}
	stmt := &parser.EvalStmt{
		Expr:     promql.PreprocessExpr(expr, start, end),
		Start:    start,
		End:      end,
		Interval: interval,
	}
	return d.parseStmt(stmt)
}

/*
difference between SelectHints & combinHint:
in prometheus, SelectHints only extract inner function for <VectorSelector> and get the max query [range]
but we may need multiple functions query in clickhouse, like: sum(rate(metric[1d])) should get only 1 point from database, not 1d
so use CombineHint to get multiple functions outside of <VectorSelector>
*/
func (d *queryAnalyzer) parseStmt(stmt *parser.EvalStmt) []model.QueryRequest {
	result := make([]model.QueryRequest, 0)
	var evalRange time.Duration
	parser.Inspect(stmt.Expr, func(node parser.Node, path []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			start, end := d.getTimeRangesForSelector(stmt, n, path, evalRange)

			queryHint := &QueryHint{
				start:    start,
				end:      end,
				step:     durationMilliseconds(stmt.Interval),
				matchers: n.LabelMatchers,
				funcs:    extractSubFunctionFromPath(path),
				query:    stmt.String(),
			}
			evalRange = 0
			result = append(result, queryHint)

			// hints := &storage.SelectHints{
			// 	Start: start,
			// 	End:   end,
			// 	Step:  durationMilliseconds(stmt.Interval),
			// 	Range: durationMilliseconds(evalRange),
			// 	Func:  extractFuncFromPath(path),
			// }
			// hints.By, hints.Grouping = extractGroupsFromPath(path)

			// prometheusHint := &prometheusHint{
			// 	hints:    hints,
			// 	matchers: n.LabelMatchers,
			// 	query:    stmt.String(),
			// }

			// result = append(result, prometheusHint)

		case *parser.MatrixSelector:
			// matrix range is the query range of inside vector, evalRange will retrive in *parser.VectorSelector case
			// e.g.: test[1h] == <MatrixSelector>, `test` == <VectorSelector>, [1h] == <Range>
			evalRange = n.Range
		}

		return nil
	})
	return result
}

func (d *queryAnalyzer) getTimeRangesForSelector(s *parser.EvalStmt, n *parser.VectorSelector, path []parser.Node, evalRange time.Duration) (int64, int64) {
	start, end := timestamp.FromTime(s.Start), timestamp.FromTime(s.End)
	subqOffset, subqRange, subqTs := subqueryTimes(path)

	if subqTs != nil {
		// The timestamp on the subquery overrides the eval statement time ranges.
		start = *subqTs
		end = *subqTs
	}

	if n.Timestamp != nil {
		// The timestamp on the selector overrides everything.
		start = *n.Timestamp
		end = *n.Timestamp
	} else {
		offsetMilliseconds := durationMilliseconds(subqOffset)
		start = start - offsetMilliseconds - durationMilliseconds(subqRange)
		end -= offsetMilliseconds
	}

	if evalRange == 0 {
		start -= durationMilliseconds(d.lookBackDelta)
	} else {
		// For all matrix queries we want to ensure that we have (end-start) + range selected
		// this way we have `range` data before the start time
		start -= durationMilliseconds(evalRange)
	}

	offsetMilliseconds := durationMilliseconds(n.OriginalOffset)
	start -= offsetMilliseconds
	end -= offsetMilliseconds

	return start, end
}

func subqueryTimes(path []parser.Node) (time.Duration, time.Duration, *int64) {
	var (
		subqOffset, subqRange time.Duration
		ts                    int64 = math.MaxInt64
	)
	for _, node := range path {
		if n, ok := node.(*parser.SubqueryExpr); ok {
			subqOffset += n.OriginalOffset
			subqRange += n.Range
			if n.Timestamp != nil {
				// The @ modifier on subquery invalidates all the offset and
				// range till now. Hence resetting it here.
				subqOffset = n.OriginalOffset
				subqRange = n.Range
				ts = *n.Timestamp
			}
		}
	}
	var tsp *int64
	if ts != math.MaxInt64 {
		tsp = &ts
	}
	return subqOffset, subqRange, tsp
}

// extracts `minimum possible` calculation unit for ck
func extractSubFunctionFromPath(p []parser.Node) []functionCall {
	funcs := make([]functionCall, 0, len(p))
	if len(p) == 0 {
		return funcs
	}
	var evalRange time.Duration
	var step time.Duration
	for i := len(p) - 1; i >= 0; i-- {
		switch n := p[i].(type) {
		case *parser.AggregateExpr:
			// AggregateExpr: sum/avg/group...
			if n.Without {
				// if group without, we can not offload this function, return funcs
				return funcs
			}
			var p float64 = 0
			if n.Param != nil {
				// p for topk(N) & quantile(N)
				if numExpr, ok := n.Param.(*parser.NumberLiteral); ok {
					p = numExpr.Val
				}
			}
			f := functionCall{Name: n.Op.String(), Grouping: n.Grouping, Range: evalRange, Param: p}
			evalRange = 0
			funcs = append(funcs, f)
		case *parser.Call:
			// Call: rate/delta/increase/x_over_time...
			f := functionCall{Name: n.Func.Name, Range: evalRange}
			if n.Args != nil {
				// p for quantile_over_time
				for _, subE := range n.Args {
					val := extractValFromSubNode(subE)
					if val > 0 {
						f.Param = val
						break
					}
				}
			}
			evalRange = 0
			funcs = append(funcs, f)
		case *parser.MatrixSelector:
			evalRange = n.Range
		case *parser.SubqueryExpr:
			// `for` loop is from inner-level to outer-leve
			// so only the inner-level subQuery step is meaningful, outside level is base on the inner step
			// only assign `step` one time
			if step == 0 {
				step = n.Step
				if n.Step == 0 {
					step = defaultNoStepSubQueryInterval
				}
				if len(funcs) > 0 {
					funcs[len(funcs)-1].SubStep = step
					step = 0
				}
			}
		case *parser.ParenExpr, *parser.StepInvariantExpr:
			// unwrap () and invariant expr
			continue
		default:
			// other Expr can not be offloaded, when we meet other `Expr`, return funcs
			return funcs
		}
	}
	return funcs
}

func extractValFromSubNode(expr parser.Expr) float64 {
	switch n := expr.(type) {
	case *parser.UnaryExpr:
		return extractValFromSubNode(n.Expr)
	case *parser.StepInvariantExpr:
		return extractValFromSubNode(n.Expr)
	case *parser.NumberLiteral:
		return n.Val
	default:
		return 0
	}
}

// get the inner function of <VectorSelector>
func extractFuncFromPath(p []parser.Node) string {
	if len(p) == 0 {
		return ""
	}
	switch n := p[len(p)-1].(type) {
	case *parser.AggregateExpr:
		return n.Op.String()
	case *parser.Call:
		return n.Func.Name
	case *parser.BinaryExpr:
		// If we hit a binary expression we terminate since we only care about functions
		// or aggregations over a single metric.
		return ""
	}
	return extractFuncFromPath(p[:len(p)-1])
}

// extractGroupsFromPath parses vector outer function and extracts grouping information if by or without was used.
func extractGroupsFromPath(p []parser.Node) (bool, []string) {
	if len(p) == 0 {
		return false, nil
	}
	switch n := p[len(p)-1].(type) {
	case *parser.AggregateExpr:
		return !n.Without, n.Grouping
	}
	return false, nil
}

func extractMetricName(matchers *[]*labels.Matcher) string {
	var metric string
	for _, v := range *matchers {
		if v.Name == labels.MetricName {
			metric = v.Value
			break
		}
	}
	return metric
}
