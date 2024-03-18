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

package model

const (
	CACHE_LABEL_STRING_TAG  = "__cache_label_string__"
	PROMETHEUS_LABELS_INDEX = "__labels_index__"
)

var RelabelFunctions = []string{"sum", "avg", "count", "min", "max", "group", "stddev", "stdvar", "count_values", "quantile"}

var MatrixCallFunctions = []string{"topk", "bottomk",
	"avg_over_time", "count_over_time", "last_over_time", "max_over_time", "min_over_time", "stddev_over_time", "sum_over_time", "present_over_time", "quantile_over_time",
	"idelta", "delta", "increase", "irate", "rate"}
