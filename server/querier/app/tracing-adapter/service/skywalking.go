/*
 * Copyright (c) 2023 Yunshan Networks
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
	"fmt"
	"net/http"

	"skywalking.apache.org/repo/goapi/query"

	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/common"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/mitchellh/mapstructure"
	"github.com/op/go-logging"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

const (
	query_url = "graphql"
	// query graphql for skywalking
	query_trace = `query queryTrace($traceId: ID!) {
	trace: queryTrace(traceId: $traceId) {
		spans {
			traceId segmentId spanId parentSpanId
			refs { traceId parentSegmentId parentSpanId type }
			serviceCode serviceInstanceName startTime endTime endpointName type peer component isError layer
			tags { key value }
			logs {
				time
				data { key value }
			}
			attachedEvents {
				startTime { seconds nanos }
				event
				endTime { seconds nanos }
				tags { key value }
				summary { key value }
			}
		}
	}
}`
)

type swGraphRequest[T any] struct {
	Query     string `json:"query"`
	Variables *T     `json:"variables"`
}

type swTraceQuery struct {
	TraceID string `json:"traceId"`
}

type swTraceResponse[T any] struct {
	Data struct {
		Trace *T `json:"trace"`
	} `json:"data"`
}

type skywalkingConfig struct {
	Auth string `mapstructure:"auth"` // basic auth
}

type SkyWalkingAdapter struct {
}

var log_sw = logging.MustGetLogger("tracing-adapter.skywalking")

func (s *SkyWalkingAdapter) GetTrace(traceID string, c *config.ExternalAPM) (*model.ExTrace, error) {
	swConfig := &skywalkingConfig{}
	err := mapstructure.Decode(c.ExtraConfig, swConfig)
	if err != nil {
		log_sw.Errorf("cannot decode skywalking extra config %v, err: %s", c.ExtraConfig, err)
		return nil, err
	}
	traces, err := s.getTrace(traceID, c, swConfig)
	if err != nil {
		return nil, err
	}
	return s.skywalkingTracesToExTraces(traces), nil
}

func (s *SkyWalkingAdapter) appendAuthHeader(auth string) map[string]string {
	header := common.DefaultContentTypeHeader()
	if auth == "" {
		return header
	}
	header["Authorization"] = fmt.Sprintf("Basic %s", auth)
	return header
}

func (s *SkyWalkingAdapter) getTrace(traceID string, c *config.ExternalAPM, swConfig *skywalkingConfig) (*query.Trace, error) {
	req := &swGraphRequest[swTraceQuery]{
		Query:     query_trace,
		Variables: &swTraceQuery{TraceID: traceID},
	}
	post_data, err := common.Serialize(req)
	if err != nil {
		log_sw.Errorf("serialize failed! err: %s", err)
		return nil, err
	}
	scheme := "http"
	if c.TLS != nil {
		scheme = "https"
	}
	result, err := common.DoRequest(http.MethodPost, fmt.Sprintf("%s://%s/%s", scheme, c.Addr, query_url), post_data, s.appendAuthHeader(swConfig.Auth), c.Timeout, c.TLS)
	if err != nil {
		log_sw.Errorf("query skywalking trace %s at %s failed! addr: %s, err: %s", traceID, c.Addr, err)
		return nil, err
	}
	traces, err := common.Deserialize[swTraceResponse[query.Trace]](result)
	if err != nil || traces == nil {
		log_sw.Errorf("deserialize failed! err: %s", err)
		return nil, err
	}
	return traces.Data.Trace, err
}

func (s *SkyWalkingAdapter) skywalkingTracesToExTraces(traces *query.Trace) *model.ExTrace {
	exTrace := &model.ExTrace{}
	exTrace.Spans = make([]model.ExSpan, 0, len(traces.Spans))
	for i := 0; i < len(traces.Spans); i++ {
		skywalkingSpan := traces.Spans[i]
		span := model.ExSpan{
			StartTimeUs:  skywalkingSpan.StartTime * 1e3, // millisecond to microsecond
			EndTimeUs:    skywalkingSpan.EndTime * 1e3,
			TraceID:      skywalkingSpan.TraceID,
			SpanID:       s.swSpanIDToDFSpanID(skywalkingSpan.SegmentID, skywalkingSpan.SpanID),
			ParentSpanID: s.swSpanIDToDFSpanID(skywalkingSpan.SegmentID, skywalkingSpan.ParentSpanID),
			SpanKind:     s.swSpanTypeToSpanKind(skywalkingSpan.Type),
			Endpoint:     *skywalkingSpan.EndpointName,
			Name:         *skywalkingSpan.EndpointName,
		}
		exTrace.Spans = append(exTrace.Spans, span)
	}
	return exTrace
}

func (s *SkyWalkingAdapter) swSpanIDToDFSpanID(segmentID string, spanID int) string {
	// DeepFlow use segmentID-spanID as DeepFlow spanID
	if spanID == -1 {
		return ""
	}
	return fmt.Sprintf("%s-%d", segmentID, spanID)
}

func (s *SkyWalkingAdapter) swSpanTypeToSpanKind(spanType string) int {
	switch spanType {
	case "Exit":
		// client-side span
		return int(v1.Span_SPAN_KIND_CLIENT)
	case "Entry":
		// server-side span
		return int(v1.Span_SPAN_KIND_SERVER)
	case "Local":
		// internal span
		return int(v1.Span_SPAN_KIND_INTERNAL)
	default:
		return int(v1.Span_SPAN_KIND_UNSPECIFIED)
	}
}
