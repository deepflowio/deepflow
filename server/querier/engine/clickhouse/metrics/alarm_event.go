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

import ()

var ALARM_EVENT_METRICS = map[string]*Metrics{}

var ALARM_EVENT_METRICS_REPLACE = map[string]*Metrics{
	"log_count": NewReplaceMetrics("1", ""),
}

func GetAlarmEventMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return ALARM_EVENT_METRICS
}
