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

package metrics

import (
	"fmt"
)

var DB_FIELD_REQUEST = fmt.Sprintf(
	"if(type IN [%d, %d],1,0)", FLOW_LOG_TYPE_REQUEST, FLOW_LOG_TYPE_SESSION,
)
var DB_FIELD_RESPONSE = fmt.Sprintf(
	"if(type IN [%d, %d],1,0)", FLOW_LOG_TYPE_RESPONSE, FLOW_LOG_TYPE_SESSION,
)
var DB_FIELD_ERROR = fmt.Sprintf(
	"if(response_status IN [%d, %d],1,0)", FLOW_LOG_EXCEPTION_CLIENT, FLOW_LOG_EXCEPTION_SERVER,
)
var DB_FIELD_CLIENT_ERROR = fmt.Sprintf(
	"if(response_status IN [%d],1,0)", FLOW_LOG_EXCEPTION_CLIENT,
)
var DB_FIELD_SERVER_ERROR = fmt.Sprintf(
	"if(response_status IN [%d],1,0)", FLOW_LOG_EXCEPTION_SERVER,
)
var DB_FIELD_SESSION_LENGTH = "if(request_length>0,request_length,0)+if(response_length>0,response_length,0)"

var L7_FLOW_LOG_METRICS = map[string]*Metrics{}

var L7_FLOW_LOG_METRICS_REPLACE = map[string]*Metrics{
	"log_count":          NewReplaceMetrics("1", ""),
	"request":            NewReplaceMetrics(DB_FIELD_REQUEST, ""),
	"response":           NewReplaceMetrics(DB_FIELD_RESPONSE, ""),
	"error":              NewReplaceMetrics(DB_FIELD_ERROR, ""),
	"client_error":       NewReplaceMetrics(DB_FIELD_CLIENT_ERROR, ""),
	"server_error":       NewReplaceMetrics(DB_FIELD_SERVER_ERROR, ""),
	"error_ratio":        NewReplaceMetrics(DB_FIELD_ERROR+"/"+DB_FIELD_RESPONSE, DB_FIELD_ERROR+"/"+DB_FIELD_RESPONSE+">=0"),
	"client_error_ratio": NewReplaceMetrics(DB_FIELD_CLIENT_ERROR+"/"+DB_FIELD_RESPONSE, DB_FIELD_CLIENT_ERROR+"/"+DB_FIELD_RESPONSE+">=0"),
	"server_error_ratio": NewReplaceMetrics(DB_FIELD_SERVER_ERROR+"/"+DB_FIELD_RESPONSE, DB_FIELD_SERVER_ERROR+"/"+DB_FIELD_RESPONSE+">=0"),
	"session_length":     NewReplaceMetrics(DB_FIELD_SESSION_LENGTH, "").SetIsAgg(false),
}

func GetL7FlowLogMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return L7_FLOW_LOG_METRICS
}
