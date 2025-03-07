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
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"skywalking.apache.org/repo/goapi/query"

	"github.com/baidubce/bce-sdk-go/util/log"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/common"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/op/go-logging"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

const (
	query_url = "graphql"
	// query graphql for skywalking
	// supported skywalking-query-protocol version: v8.0.0+
	query_trace = `query queryTrace($traceId: ID!) {
	trace: queryTrace(traceId: $traceId) {
		spans {
			traceId segmentId spanId parentSpanId
			refs { traceId parentSegmentId parentSpanId type }
			serviceCode serviceInstanceName startTime endTime endpointName type peer component isError layer
			tags { key value }
		}
	}
}`
)

const (
	// https://github.com/apache/skywalking-query-protocol/blob/master/trace.graphqls#L86
	SpanTypeLocal  = "Local"
	SpanTypeClient = "Exit"
	SpanTypeServer = "Entry"

	AttributeURL               = "url"
	AttributeHttpURL           = "http.url"
	AttributeHTTPMethod        = "http.method"
	AttributeHttpScheme        = "http.scheme"
	AttributeHTTPStatus        = "http.status"
	AttributeHTTPStatus_Code   = "http.status_code"
	AttributeHTTPStatusCode    = "http.status.code"
	AttributeCacheCmd          = "cache.cmd"
	AttributeCacheKey          = "cache.key"
	AttributeDbType            = "db.type"
	AttributeDbSystem          = "db.system"
	AttributeDbStatement       = "db.statement"
	AttributeDbOperation       = "db.operation"
	AttributeRpcMethod         = "rpc.method"
	AttributeRpcSystem         = "rpc.system"
	AttributeRpcService        = "rpc.service"
	AttributeMessagingURL      = "messaging.url"
	AttributeMessagingSystem   = "messaging.system"
	AttributeMessagingProtocol = "messaging.protocol"

	// layer possible values: Unknown, Database, RPCFramework, Http, MQ and Cache
	// ref: https://github.com/apache/skywalking-query-protocol/blob/master/trace.graphqls#L94
	LayerUnknown  = "Unknown"
	LayerDatabase = "Database"
	LayerRPC      = "RPCFramework"
	LayerHTTP     = "Http"
	LayerCache    = "Cache"
	LayerMQ       = "MQ"
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
	if err != nil || traces == nil {
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
	if err != nil || result == nil {
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
		if skywalkingSpan == nil {
			continue
		}
		span := model.ExSpan{
			Name:            *skywalkingSpan.EndpointName,
			ID:              s.generateSwUniqueID(skywalkingSpan.SegmentID, skywalkingSpan.SpanID, skywalkingSpan.StartTime*1e3, i),
			StartTimeUs:     skywalkingSpan.StartTime * 1e3,
			EndTimeUs:       skywalkingSpan.EndTime * 1e3,
			TapSide:         s.swSpanTypeToTapSide(skywalkingSpan.Type),
			TraceID:         skywalkingSpan.TraceID,
			SpanID:          s.swSpanIDToDFSpanID(skywalkingSpan.SegmentID, skywalkingSpan.SpanID),
			ParentSpanID:    s.swRefSpanToParentSpanID(skywalkingSpan.SegmentID, skywalkingSpan.ParentSpanID, &skywalkingSpan.Refs),
			SpanKind:        s.swSpanTypeToSpanKind(skywalkingSpan.Type),
			Endpoint:        *skywalkingSpan.EndpointName,
			AppService:      skywalkingSpan.ServiceCode, // service name
			AppInstance:     skywalkingSpan.ServiceInstanceName,
			ServiceUname:    skywalkingSpan.ServiceCode,
			RequestResource: *skywalkingSpan.EndpointName, // maybe overwrite by tags
			SignalSource:    model.L7_FLOW_SIGNAL_SOURCE_OTEL,
			Attribute:       s.swTagsToAttributes(skywalkingSpan.Tags),
		}
		s.swTagsToSpanRequestInfo(*skywalkingSpan.Layer, skywalkingSpan.Tags, &span)
		exTrace.Spans = append(exTrace.Spans, span)
	}
	return exTrace
}

func (s *SkyWalkingAdapter) generateSwUniqueID(segmentID string, spanID int, startTimeUs int64, index int) uint64 {
	swSegmentUUID := segmentID
	if len(segmentID) > 36 {
		// uuid length 36: see in rfc4122
		// for segmentID like [9be33fe4ae364a2492e4e59f56cef454.49.16944286788056842], only need first part
		swSegmentUUID = segmentID[:32]
	}
	// try to parse segmentID, if failed, use startime as parse segmentID
	uid, err := uuid.Parse(swSegmentUUID)
	var encodeID uint64
	if err == nil {
		encodeID = uint64(uid.ID())
	} else {
		encodeID = uint64(startTimeUs)
	}
	// high 32 bits: encodeID
	// mid 8 bits: spanID
	// last 24 bits: index * 0xfff1
	// should confirm ID is unique in one trace, and 0xfff1 is the biggest prime number in 0-65535, it means nothing
	return encodeID<<32 | uint64(spanID&0xff)<<16 | uint64(index*0xfff1)&0xffffff
}

func (s *SkyWalkingAdapter) swSpanIDToDFSpanID(segmentID string, spanID int) string {
	// DeepFlow use segmentID-spanID as DeepFlow spanID
	if spanID == -1 {
		return ""
	}
	return fmt.Sprintf("%s-%d", segmentID, spanID)
}

func (s *SkyWalkingAdapter) swRefSpanToParentSpanID(segmentID string, parentSpanID int, refSpan *[]*query.Ref) string {
	if parentSpanID == -1 {
		if refSpan != nil && len(*refSpan) > 0 {
			// in opentracing, a span only have ONE parent now, so identified ONE parent here
			// but remember in batch cosumer case, MQ/async batch process, there could be multiple refs
			refParent := (*refSpan)[0]
			if refParent != nil {
				return fmt.Sprintf("%s-%d", refParent.ParentSegmentID, refParent.ParentSpanID)
			}
		} else {
			return ""
		}
	}
	return fmt.Sprintf("%s-%d", segmentID, parentSpanID)
}

func (s *SkyWalkingAdapter) swSpanTypeToSpanKind(spanType string) int {
	switch spanType {
	case SpanTypeClient:
		// client-side span
		return int(v1.Span_SPAN_KIND_CLIENT)
	case SpanTypeServer:
		// server-side span
		return int(v1.Span_SPAN_KIND_SERVER)
	case SpanTypeLocal:
		// internal span
		return int(v1.Span_SPAN_KIND_INTERNAL)
	default:
		return int(v1.Span_SPAN_KIND_UNSPECIFIED)
	}
}

func (s *SkyWalkingAdapter) swSpanTypeToTapSide(spanType string) string {
	switch spanType {
	case SpanTypeClient:
		// client-side span
		return "c-app"
	case SpanTypeServer:
		// server-side span
		return "s-app"
	case SpanTypeLocal:
		// internal span
		return "app"
	default:
		return "app"
	}
}

func (s *SkyWalkingAdapter) swTagsToAttributes(tags []*query.KeyValue) map[string]string {
	attr := make(map[string]string, len(tags))
	for _, v := range tags {
		attr[v.Key] = *v.Value
	}
	return attr
}

func (s *SkyWalkingAdapter) swTagsToSpanRequestInfo(layer string, tags []*query.KeyValue, span *model.ExSpan) {
	if tags == nil {
		return
	}
	if layer == LayerHTTP {
		span.L7Protocol, span.L7ProtocolStr, span.L7ProtocolEnum = int(datatype.L7_PROTOCOL_HTTP_1), datatype.L7_PROTOCOL_HTTP_1.String(false), datatype.L7_PROTOCOL_HTTP_1.String(false)
	}
	s.getTagValue(tags, span)
	// for which not match l7protocol, but found l7protocolstr by tag.value, try to match
	if span.L7Protocol == 0 && len(span.L7ProtocolStr) > 0 {
		l7ProtocolStrLower := strings.ToLower(span.L7ProtocolStr)
		for l7ProtocolEnumStr, l7ProtocolMap := range datatype.L7ProtocolStringMap {
			if strings.Contains(l7ProtocolEnumStr, l7ProtocolStrLower) {
				span.L7Protocol = int(l7ProtocolMap)
				span.L7ProtocolEnum = l7ProtocolEnumStr
				break
			}
		}
	}
}

func (s *SkyWalkingAdapter) getTagValue(tags []*query.KeyValue, span *model.ExSpan) {
	httpURL := ""
	for _, v := range tags {
		if span.L7Protocol == 0 && len(span.L7ProtocolStr) == 0 {
			// if layer != http (maybe is unknown), but have some http attributes, it's http
			if strings.HasPrefix(v.Key, "http") {
				span.L7Protocol, span.L7ProtocolStr, span.L7ProtocolEnum = int(datatype.L7_PROTOCOL_HTTP_1), datatype.L7_PROTOCOL_HTTP_1.String(false), datatype.L7_PROTOCOL_HTTP_1.String(false)
			}
		}
		switch v.Key {
		case AttributeURL, AttributeHttpURL:
			httpURL = *v.Value
		case AttributeHTTPMethod, AttributeCacheCmd, AttributeDbOperation, AttributeRpcMethod:
			span.RequestType = *v.Value
		case AttributeHTTPStatusCode, AttributeHTTPStatus_Code, AttributeHTTPStatus:
			code, err := strconv.Atoi(*v.Value)
			if err == nil {
				span.ResponseCode = code
			}
		case AttributeDbStatement, AttributeCacheKey:
			span.RequestResource = *v.Value
		case AttributeDbType, AttributeDbSystem, AttributeHttpScheme, AttributeRpcSystem, AttributeMessagingSystem, AttributeMessagingProtocol:
			span.L7ProtocolStr = *v.Value
		}
	}

	if span.RequestResource == "" && httpURL != "" {
		parsedURLPath, err := ParseUrlPath(httpURL)
		if err != nil {
			log.Warnf("query skywalking data get http.url (%s) parsed failed : %s", httpURL, err)
		} else {
			span.RequestResource = parsedURLPath
		}
	}
	span.ResponseStatus = int(HttpCodeToResponseStatus(span.ResponseCode))
}
