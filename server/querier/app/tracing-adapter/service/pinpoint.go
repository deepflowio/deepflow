/*
 * Copyright (c) 2025 Yunshan Networks
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
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/common"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/mitchellh/mapstructure"
	"github.com/op/go-logging"
)

const (
	// http://10.50.1.108:8080/transactionInfo.pinpoint?agentId=app-in-docker&spanId=-800223468020513054&traceId=app-in-docker%5E1764398520495%5E16&focusTimestamp=1764399661457&useStatisticsAgentState=false
	pp_query_url = "transactionInfo.pinpoint"
)

const ()

type ppTraceResponse[T any] struct {
	Data struct {
		Trace *T `json:"trace"`
	} `json:"data"`
}

type pinpointConfig struct {
	Auth string `mapstructure:"auth"` // basic auth
}

type PinpointAdapter struct {
}

var log_pp = logging.MustGetLogger("tracing-adapter.pinpoint")

func (s *PinpointAdapter) GetTrace(traceID string, c *config.ExternalAPM) (*model.ExTrace, error) {
	log_pp.Infof("pinpoint GetTrace  %s  %+v", traceID, c)
	ppConfig := &pinpointConfig{}
	err := mapstructure.Decode(c.ExtraConfig, ppConfig)
	if err != nil {
		log_pp.Errorf("cannot decode pinpoint extra config %v, err: %s", c.ExtraConfig, err)
		return nil, err
	}
	traces, err := s.getTrace(traceID, c, ppConfig)
	if err != nil || traces == nil {
		return nil, err
	}
	return s.pinpointTracesToExTraces(traces), nil
}

func (s *PinpointAdapter) appendAuthHeader(auth string) map[string]string {
	header := common.DefaultContentTypeHeader()
	if auth == "" {
		return header
	}
	header["Authorization"] = fmt.Sprintf("Basic %s", auth)
	return header
}

func (s *PinpointAdapter) getTrace(traceID string, c *config.ExternalAPM, ppConfig *pinpointConfig) (*TraceResponse, error) {
	scheme := "http"
	if c.TLS != nil {
		scheme = "https"
	}
	pp_trace := fmt.Sprintf("traceId=%s", url.QueryEscape(traceID))
	result, err := common.DoRequest(http.MethodGet, fmt.Sprintf("%s://%s/%s?%s", scheme, c.Addr, pp_query_url, pp_trace), nil, s.appendAuthHeader(ppConfig.Auth), c.Timeout, c.TLS)
	if err != nil || result == nil {
		log_pp.Errorf("query pinpoint trace %s at %s failed! addr: %s, err: %s", traceID, c.Addr, err)
		return nil, err
	}

	var resp TraceResponse
	err = json.Unmarshal(result, &resp)
	if err != nil {
		log_pp.Errorf("parse json failed, err: %s", traceID, c.Addr, err)
		return nil, err
	}

	_, err = ParseCallStack(&resp)
	if err != nil {
		return nil, err
	}

	return &resp, err
}

func (s *PinpointAdapter) pinpointTracesToExTraces(traces *TraceResponse) *model.ExTrace {
	exTrace := &model.ExTrace{}
	exTrace.Spans = make([]model.ExSpan, 0, len(traces.CallStack))
	for i := 0; i < len(traces.CallStacks); i++ {
		pinpointSpan := traces.CallStacks[i]
		if !pinpointSpan.IsMethod {
			continue
		}

		l7Protocol := 0
		l7ProtocolStr, l7ProtocolEnum := "", ""
		endpoint := ""
		// get attribute
		attribute := make(map[string]string)
		id := pinpointSpan.Id
		for j := range traces.CallStacks {
			s := traces.CallStacks[j]
			if s.ParentId == id && !s.IsMethod {
				attribute[s.Title] = s.Arguments
				if strings.Contains(s.Title, "http") {
					l7Protocol = 20
					l7ProtocolStr, l7ProtocolEnum = "http", "HTTP"
				} else if s.Title == "ENDPOINT" {
					endpoint = s.Arguments
				}
			}
		}

		responseStatus := 0
		if pinpointSpan.HasException {
			responseStatus = 3 // server error
		}

		span := model.ExSpan{
			Name:            pinpointSpan.Arguments,
			RequestType:     pinpointSpan.Title,
			ID:              rand.New(rand.NewSource(time.Now().UnixNano())).Uint64(),
			StartTimeUs:     pinpointSpan.BeginTime * 1e3,
			EndTimeUs:       pinpointSpan.EndTime * 1e3,
			TapSide:         "app",
			TraceID:         traces.TransactionId,
			SpanID:          pinpointSpan.Id,
			ParentSpanID:    pinpointSpan.ParentId,
			SpanKind:        1, // SPAN_KIND_INTERNAL
			Endpoint:        endpoint,
			AppService:      pinpointSpan.ApplicationName,
			ServiceUname:    pinpointSpan.ApplicationName,
			RequestResource: pinpointSpan.Arguments,
			SignalSource:    model.L7_FLOW_SIGNAL_SOURCE_OTEL,
			Attribute:       attribute,
			ResponseStatus:  responseStatus,
			L7Protocol:      l7Protocol,
			L7ProtocolStr:   l7ProtocolStr,
			L7ProtocolEnum:  l7ProtocolEnum,
		}
		exTrace.Spans = append(exTrace.Spans, span)
	}
	log_pp.Infof("return spans: %+v", exTrace)
	return exTrace
}

type TraceResponse struct {
	LogLinkEnable          bool            `json:"logLinkEnable"`
	LogButtonName          string          `json:"logButtonName"`
	DisableButtonMessage   string          `json:"disableButtonMessage"`
	LogPageUrl             string          `json:"logPageUrl"`
	TransactionId          string          `json:"transactionId"`
	SpanId                 int64           `json:"spanId"`
	CompleteState          string          `json:"completeState"`
	ApplicationName        string          `json:"applicationName"`
	ApplicationId          string          `json:"applicationId"`
	AgentId                string          `json:"agentId"`
	AgentName              string          `json:"agentName"`
	LoggingTransactionInfo bool            `json:"loggingTransactionInfo"`
	CallStackIndex         map[string]int  `json:"callStackIndex"`
	CallStack              [][]interface{} `json:"callStack"`
	CallStacks             []CallStackEntry
	ApplicationMapData     json.RawMessage `json:"applicationMapData"`
}

type CallStackEntry struct {
	ApplicationName string
	BeginTime       int64
	EndTime         int64
	HasException    bool
	ServiceType     string
	Depth           int
	Id              string
	ParentId        string
	IsMethod        bool
	HasChild        bool
	ApiType         string
	Endpoint        string
	ExecTime        string
	Gap             string
	ElapsedTime     string
	Arguments       string
	Title           string
	// ...你可根据 callStackIndex 继续扩展
}

func ParseCallStack(resp *TraceResponse) ([]CallStackEntry, error) {
	idx := resp.CallStackIndex
	var out []CallStackEntry

	for _, row := range resp.CallStack {
		entry := CallStackEntry{}

		get := func(key string) interface{} {
			if pos, ok := idx[key]; ok && pos < len(row) {
				return row[pos]
			}
			return nil
		}

		entry.ApplicationName, _ = get("applicationName").(string)

		if v := get("begin"); v != nil {
			switch n := v.(type) {
			case float64:
				entry.BeginTime = int64(n)
			}
		}

		if v := get("end"); v != nil {
			switch n := v.(type) {
			case float64:
				entry.EndTime = int64(n)
			}
		}

		entry.HasException, _ = get("hasException").(bool)

		entry.ServiceType, _ = get("apiType").(string)
		entry.Id, _ = get("id").(string)
		entry.ParentId, _ = get("parentId").(string)
		entry.IsMethod, _ = get("isMethod").(bool)
		entry.HasChild, _ = get("hasChild").(bool)
		entry.Endpoint, _ = get("endPoint").(string)
		entry.ExecTime, _ = get("executeTime").(string)
		entry.Gap, _ = get("gap").(string)
		entry.ElapsedTime, _ = get("elapsedTime").(string)
		entry.Arguments, _ = get("arguments").(string)
		entry.Title, _ = get("title").(string)

		out = append(out, entry)
	}
	resp.CallStacks = out
	return out, nil
}
