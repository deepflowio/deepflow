package prometheus

import (
	"context"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
	//"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"strconv"
)

type RemoteReadQuerierable struct {
	Args *common.PromQueryParams
	Ctx  context.Context
}

func (q *RemoteReadQuerierable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	return &RemoteReadQuerier{Args: q.Args, Ctx: q.Ctx}, nil
}

type RemoteReadQuerier struct {
	Args *common.PromQueryParams
	Ctx  context.Context
}

// For PromQL instant query
func (q *RemoteReadQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	startTimeS, err := (strconv.ParseFloat(q.Args.StartTime, 64))
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	startTimeMs := int64(startTimeS * 1000)
	endTimeS, err := (strconv.ParseFloat(q.Args.EndTime, 64))
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	endTimeMs := int64(endTimeS * 1000)
	prompbQuery, err := remote.ToQuery(startTimeMs, endTimeMs, matchers, hints)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	req := &prompb.ReadRequest{
		Queries:               []*prompb.Query{prompbQuery},
		AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
	}
	resp, err := PromReaderExecute(req, q.Ctx)
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

type RemoteReadRangeQuerierable struct {
	Args *common.PromQueryParams
	Ctx  context.Context
}

func (q *RemoteReadRangeQuerierable) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	return &RemoteReadRangeQuerier{Args: q.Args, Ctx: q.Ctx}, nil
}

type RemoteReadRangeQuerier struct {
	Args *common.PromQueryParams
	Ctx  context.Context
}

// For PromQL range query
func (q *RemoteReadRangeQuerier) Select(sortSeries bool, hints *storage.SelectHints, matchers ...*labels.Matcher) storage.SeriesSet {
	startS, err := (strconv.ParseFloat(q.Args.StartTime, 64))
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	endS, err := (strconv.ParseFloat(q.Args.EndTime, 64))
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	startMs := int64(startS * 1000)
	endMs := int64(endS * 1000)
	prompbQuery, err := remote.ToQuery(startMs, endMs, matchers, hints)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	req := &prompb.ReadRequest{
		Queries:               []*prompb.Query{prompbQuery},
		AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{prompb.ReadRequest_STREAMED_XOR_CHUNKS},
	}
	resp, err := PromReaderExecute(req, q.Ctx)
	if err != nil {
		log.Error(err)
		return storage.ErrSeriesSet(err)
	}
	return remote.FromQueryResult(sortSeries, resp.Results[0])
}

func (q *RemoteReadRangeQuerier) LabelValues(name string, matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (q *RemoteReadRangeQuerier) LabelNames(matchers ...*labels.Matcher) ([]string, storage.Warnings, error) {
	return nil, nil, nil
}

func (q *RemoteReadRangeQuerier) Close() error {
	return nil
}
