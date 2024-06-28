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

package config

import (
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("l7Tracing")

type L7TracingConfig struct {
	LogFile             string `default:"/var/log/app.log" yaml:"log-file"`
	LogLevel            string `default:"info" yaml:"log-level"`
	HttpRequestTimeout  int    `default:"600" yaml:"http_request_timeout"`
	HttpResponseTimeout int    `default:"600" yaml:"http_response_timeout"`
	ListenPort          int    `default:"20418" yaml:"listen-port"`
	Spec                Spec   `yaml:"spec"`
}

type Spec struct {
	L7TracingLimit                       int  `default:"100" yaml:"l7_tracing_limit"`
	NetworkDelayUs                       int  `default:"1000000" yaml:"network_delay_us"`
	AllowMultipleTraceIDsInTracingResult bool `default:"false" yaml:"allow_multiple_trace_ids_in_tracing_result"`
	CallApmApiToSupplementTrace          bool `default:"false" yaml:"call_apm_api_to_supplement_trace"`
}
