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

package model

type ExSpan struct {
	Name            string `json:"name"`
	ID              uint64 `json:"_id"`           // unique id
	StartTimeUs     int64  `json:"start_time_us"` // microseconds
	EndTimeUs       int64  `json:"end_time_us"`
	TapSide         string `json:"tap_side"` // spankind=server: s-app/ spankind=client: c-app/ spankind=internal: app
	L7Protocol      int    `json:"l7_protocol"`
	L7ProtocolStr   string `json:"l7_protocol_str"`
	TraceID         string `json:"trace_id"`
	SpanID          string `json:"span_id"`
	ParentSpanID    string `json:"parent_span_id"`
	SpanKind        int    `json:"span_kind"` // client/server/internal
	Endpoint        string `json:"endpoint"`
	RequestType     string `json:"request_type"`     // method
	RequestResource string `json:"request_resource"` // path
	ResponseStatus  int    `json:"response_status"`
	AppService      string `json:"app_service"`   // service name
	AppInstance     string `json:"app_instance"`  // service instance name
	ServiceUname    string `json:"service_uname"` // equals app_service

	Attribute map[string]string `json:"attribute"`
}

type ExTrace struct {
	Spans []ExSpan `json:"spans"`
}

type ExTraceResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   any    `json:"data,omitempty"`
}
