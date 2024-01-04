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
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/config"
)

type RemoteReadQuerierable struct {
	Args                *model.PromQueryParams
	Ctx                 context.Context
	MatchMetricNameFunc func(*[]*labels.Matcher) string
	sql                 []string
	query_time          []float64
	reader              *prometheusReader
}

func (q *RemoteReadQuerierable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	return &RemoteReadQuerier{Args: q.Args, Ctx: q.Ctx, Querierable: q, reader: q.reader}, nil
}

type RemoteReadQuerier struct {
	Args        *model.PromQueryParams
	Ctx         context.Context
	Querierable *RemoteReadQuerierable
	reader      *prometheusReader
}

// For PromQL instant query
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

	if config.Cfg.Prometheus.RequestQueryWithDebug {
		// get span from context
		span := trace.SpanFromContext(q.Ctx)
		span.SetAttributes(attribute.Float64("promql.query.range", math.Trunc((queryRange.Minutes()+0.5/math.Pow10(2))*math.Pow10(2))/math.Pow10(2)))
		metric := q.Querierable.MatchMetricNameFunc(&matchers)
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
	resp, sql, query_time, err := q.reader.promReaderExecute(q.Ctx, req, q.Args.Debug)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	if q.Args.Debug {
		if q.Querierable.sql == nil {
			q.Querierable.sql = make([]string, 0)
		}
		if q.Querierable.query_time == nil {
			q.Querierable.query_time = make([]float64, 0)
		}
		q.Querierable.sql = append(q.Querierable.sql, sql)
		q.Querierable.query_time = append(q.Querierable.query_time, query_time)
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
