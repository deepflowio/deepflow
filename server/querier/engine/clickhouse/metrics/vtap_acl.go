/*
 * Copyright (c) 2022 Yunshan Networks
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

var VTAP_ACL_METRICS = map[string]*Metrics{}

var VTAP_ACL_METRICS_REPLACE = map[string]*Metrics{
	"l3_byte": NewReplaceMetrics("l3_byte_tx+l3_byte_rx", ""),
	"l4_byte": NewReplaceMetrics("l4_byte_tx+l4_byte_rx", ""),
}

func GetVtapAclMetrics() map[string]*Metrics {
	// TODO: 特殊指标量修改
	return VTAP_ACL_METRICS
}
