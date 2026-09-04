/**
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

package cache

import (
	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// PrometheusCache defines the unified interface for all Prometheus cache operations.
// This interface should be used by external modules (like encoder) instead of direct Cache struct access.
type PrometheusCache interface {
	GetORG() *common.ORG

	// MetricName operations
	GetMetricNameID(name string) (int, bool)
	GetMetricNameToID() map[string]int
	AddMetricNames(batch []*metadbmodel.PrometheusMetricName)
	AddMetricNamesFromGrpc(batch []*controller.PrometheusMetricName)

	// LabelName operations
	GetLabelNameID(name string) (int, bool)
	GetLabelNameByID(id int) (string, bool)
	AddLabelNames(batch []*metadbmodel.PrometheusLabelName)
	AddLabelNamesFromGrpc(batch []*controller.PrometheusLabelName)

	// LabelValue operations
	GetLabelValueID(value string) (int, bool)
	GetLabelValueByID(id int) (string, bool)
	AddLabelValues(batch []*metadbmodel.PrometheusLabelValue)
	AddLabelValuesFromGrpc(batch []*controller.PrometheusLabelValue)

	// Label operations
	GetLabelID(name, value string) (int, bool)
	GetLabelKeyToID() map[LabelKey]int
	AddLabels(batch []*metadbmodel.PrometheusLabel)
	AddLabelsFromGrpc(batch []*controller.PrometheusLabel)

	// Layout operations
	GetMetricAndAPPLabelLayout() map[LayoutKey]uint8
	GetMetricAndAPPLabelLayoutIndex(key LayoutKey) (uint8, bool)
	AddMetricAndAPPLabelLayoutsFromGrpc(batch []*controller.PrometheusMetricAPPLabelLayout)

	// Refresh operations
	Refresh(wait bool) error
}
