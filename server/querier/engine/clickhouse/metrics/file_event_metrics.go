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

package metrics

// FILE_EVENT_METRICS_METRICS contains metrics definitions for file event aggregation
// These metrics are loaded dynamically from db_descriptions files
// during system initialization
var FILE_EVENT_METRICS_METRICS = map[string]*Metrics{}

// metrics to clickhouse field mapping, no need to replace
var FILE_EVENT_METRICS_METRICS_REPLACE = map[string]*Metrics{
	"avg_duration": NewReplaceMetrics("duration/count", "count>0"),
}

func GetFileEventMetricsMetrics() map[string]*Metrics {
	return FILE_EVENT_METRICS_METRICS
}
