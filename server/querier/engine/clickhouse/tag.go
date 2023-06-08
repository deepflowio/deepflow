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

package clickhouse

import (
	"context"
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

func GetTagTranslator(name, alias, db, table string) (Statement, string, error) {
	var stmt Statement
	selectTag := name
	if alias != "" {
		selectTag = alias
	}
	labelType := ""
	tagItem, ok := tag.GetTag(strings.Trim(name, "`"), db, table, "default")
	if !ok {
		name := strings.Trim(name, "`")
		if strings.HasPrefix(name, "k8s.label.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.label.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		} else if strings.HasPrefix(name, "cloud.tag.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("cloud_tag_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("cloud_tag_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("cloud_tag", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "cloud.tag.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		} else if strings.HasPrefix(name, "os.app.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("os_app_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("os_app_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("os_app", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "os.app.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		} else if strings.HasPrefix(name, "tag.") || strings.HasPrefix(name, "attribute.") {
			if strings.HasPrefix(name, "tag.") {
				if db == "prometheus" {
					nameNoPreffix := strings.TrimPrefix(name, "tag.")
					if metricID, ok := Prometheus.MetricNameToID[table]; ok {
						if labelNameID, ok := Prometheus.LabelNameToID[nameNoPreffix]; ok {
							// Determine whether the tag is app_label or target_label
							if appLabelColumnIndex, ok := Prometheus.MetricAppLabelLayout[table+", "+nameNoPreffix]; ok {
								labelType = "app"
								TagTranslatorStr := fmt.Sprintf("dictGet(flow_tag.app_label_map, 'label_value', (%d, %d, app_label_value_id_%d))", metricID, labelNameID, appLabelColumnIndex)
								stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag, DataBase: "prometheus", Table: table}
							} else {
								labelType = "target"
								TagTranslatorStr := fmt.Sprintf("dictGet(flow_tag.target_label_map, 'label_value', (%d, %d, target_id))", metricID, labelNameID)
								stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag, DataBase: "prometheus", Table: table}
							}
						}
					}
					return stmt, labelType, nil
				}
				tagItem, ok = tag.GetTag("tag.", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("attribute.", db, table, "default")
			}
			nameNoPreffix := strings.TrimPrefix(name, "tag.")
			nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmt = &SelectTag{Value: TagTranslatorStr, Alias: selectTag}
		}
	} else {
		if name == "metrics" {
			tagTranslator := ""
			if db == "flow_log" {
				tagTranslator = fmt.Sprintf(tagItem.TagTranslator, "metrics_names", "metrics_values")
			} else {
				tagTranslator = fmt.Sprintf(tagItem.TagTranslator, "metrics_float_names", "metrics_float_values")

			}
			stmt = &SelectTag{Value: tagTranslator, Alias: selectTag}
		} else if name == "tag" && db == "prometheus" {
			tagTranslator := "toString(target_id)"
			if appLabelMaxIndex, ok := Prometheus.MetricNameToMaxIndex[table]; ok {
				appLabelTag := ""
				for i := 1; i <= appLabelMaxIndex; i++ {
					appLabelTag += fmt.Sprintf(",',',toString(app_label_value_id_%d)", i)
				}
				tagTranslator += appLabelTag
				tagTranslator = fmt.Sprintf("concat(%s)", tagTranslator)
			}
			stmt = &SelectTag{Value: tagTranslator, Alias: selectTag, DataBase: "prometheus", Table: table}
		} else if tagItem.TagTranslator != "" {
			if name != "packet_batch" || table != "l4_packet" {
				stmt = &SelectTag{Value: tagItem.TagTranslator, Alias: selectTag}
			}
		} else if alias != "" {
			stmt = &SelectTag{Value: name, Alias: selectTag}
		} else {
			stmt = &SelectTag{Value: selectTag}
		}
	}
	return stmt, labelType, nil
}

func GetSelectMetricIDFilter(name, as, db, table string) (view.Node, bool) {
	if (name == "value" || name == "tag") && db == "prometheus" {
		if metricID, ok := Prometheus.MetricNameToID[table]; ok {
			filter := fmt.Sprintf("metric_id=%d", metricID)
			return &view.Expr{Value: "(" + filter + ")"}, true
		}
	}
	return &view.Expr{}, false
}

func GetMetricsTag(name string, alias string, db string, table string, ctx context.Context) (Statement, error) {
	metricStruct, ok := metrics.GetMetrics(strings.Trim(name, "`"), db, table, ctx)
	if !ok {
		return nil, nil
	}
	if alias == "" && metricStruct.DBField != name {
		alias = name
	}
	return &SelectTag{Value: metricStruct.DBField, Alias: alias}, nil
}

func GetDefaultTag(name string, alias string) Statement {
	return &SelectTag{Value: name, Alias: alias}
}

type SelectTag struct {
	DataBase string
	Table    string
	Value    string
	Alias    string
	Flag     int
	Withs    []view.Node
}

func (t *SelectTag) Format(m *view.Model) {
	m.AddTag(&view.Tag{Value: t.Value, Alias: t.Alias, Flag: t.Flag, Withs: t.Withs})
	if common.IsValueInSliceString(t.Value, []string{"tap_port", "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1"}) {
		alias := t.Value
		if t.Alias != "" {
			alias = t.Alias
		}
		m.AddCallback(t.Value, MacTranslate([]interface{}{t.Value, alias}))
	}
	if t.Value == "packet_batch" {
		m.AddCallback(t.Value, packet_batch.PacketBatchFormat([]interface{}{}))
	}
}
