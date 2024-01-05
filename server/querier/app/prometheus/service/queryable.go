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
	"math"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
)

type RemoteReadQuerierable struct {
	Args *model.PromQueryParams
	Ctx  context.Context

	reader     *prometheusReader
	queryStats []model.PromQueryStats
}

func (q *RemoteReadQuerierable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	querier := &RemoteReadQuerier{Args: q.Args, Ctx: q.Ctx, Querierable: q, reader: q.reader}
	if q.Args.Debug {
		q.queryStats = make([]model.PromQueryStats, 0)
	}
	return querier, nil
}

func (q *RemoteReadQuerierable) GetSQLQuery() []model.PromQueryStats {
	return q.queryStats
}

func (q *RemoteReadQuerierable) BindSelectedCallBack(qry promql.Query) {
	// not implement
}

func (q *RemoteReadQuerierable) AfterQueryExec(qry promql.Query) {
	// not implement
}

type RemoteReadQuerier struct {
	Args        *model.PromQueryParams
	Ctx         context.Context
	Querierable *RemoteReadQuerierable
	reader      *prometheusReader
}

func (q *RemoteReadQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	startTimeS, err := parseTime(q.Args.StartTime)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	endTimeS, err := parseTime(q.Args.EndTime)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	queryRange := time.Duration(hints.End-hints.Start) * time.Millisecond

	if q.Args.Debug {
		// get span from context
		span := trace.SpanFromContext(q.Ctx)
		span.SetAttributes(attribute.Float64("promql.query.range", math.Trunc((queryRange.Minutes()+0.5/math.Pow10(2))*math.Pow10(2))/math.Pow10(2)))
		metric := extractMetricName(&matchers)
		// append metric names
		// target/app labels would be append after query ck finished, see <remote_read.go#82>
		span.SetAttributes(attribute.String("promql.query.metric.name", metric))
	}

	prompbQuery, err := remote.ToQuery(startTimeS.UnixMilli(), endTimeS.UnixMilli(), matchers, hints)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	req := &prompb.ReadRequest{
		Queries:               []*prompb.Query{prompbQuery},
		AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
	}
	resp, querierSql, sql, duration, err := q.reader.promReaderExecute(q.Ctx, req, q.Args.Debug)
	if q.Args.Debug {
		q.Querierable.queryStats = append(q.Querierable.queryStats, model.PromQueryStats{SQL: sql, QuerierSQL: querierSql, Duration: duration})
	}
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	return remote.FromQueryResult(sortSeries, resp.Results[0])
}

func (q *RemoteReadQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (q *RemoteReadQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (q *RemoteReadQuerier) Close() error {
	return nil
}
