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
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/querier/common"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/packet_batch"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

func GetTagTranslator(name, alias, db, table string) ([]Statement, string, error) {
	var stmts []Statement
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
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
		} else if strings.HasPrefix(name, "k8s.annotation.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_annotation_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_annotation_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_annotation", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.annotation.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix, nameNoPreffix, nameNoPreffix)
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
		} else if strings.HasPrefix(name, "k8s.env.") {
			if strings.HasSuffix(name, "_0") {
				tagItem, ok = tag.GetTag("k8s_env_0", db, table, "default")
			} else if strings.HasSuffix(name, "_1") {
				tagItem, ok = tag.GetTag("k8s_env_1", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("k8s_env", db, table, "default")
			}
			nameNoSuffix := strings.TrimSuffix(name, "_0")
			nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
			nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.env.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
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
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
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
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
		} else if slices.Contains(tag.AUTO_CUSTOM_TAG_NAMES, name) {
			autoTagMap := tagItem.TagTranslatorMap
			autoTagSlice := []string{}
			for autoTagKey, _ := range autoTagMap {
				autoTagSlice = append(autoTagSlice, autoTagKey)
			}
			sort.Strings(autoTagSlice)
			for _, autoTagKey := range autoTagSlice {
				if autoTagMap[autoTagKey] != "" {
					stmts = append(stmts, &SelectTag{Value: autoTagMap[autoTagKey], Alias: "`" + autoTagKey + "`"})
				} else {
					stmts = append(stmts, &SelectTag{Value: "`" + autoTagKey + "`"})
				}
			}
			// callback
			stmts = append(stmts, &SelectTag{Value: name})
		} else if strings.HasPrefix(name, "tag.") || strings.HasPrefix(name, "attribute.") {
			if strings.HasPrefix(name, "tag.") {
				if db == chCommon.DB_NAME_PROMETHEUS {
					TagTranslatorStr, labelType, err := GetPrometheusSingleTagTranslator(name, table)
					if err != nil {
						return nil, "", err
					}
					stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
					return stmts, labelType, nil
				}
				tagItem, ok = tag.GetTag("tag.", db, table, "default")
			} else {
				tagItem, ok = tag.GetTag("attribute.", db, table, "default")
			}
			nameNoPreffix := strings.TrimPrefix(name, "tag.")
			nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
			TagTranslatorStr := fmt.Sprintf(tagItem.TagTranslator, nameNoPreffix)
			stmts = append(stmts, &SelectTag{Value: TagTranslatorStr, Alias: selectTag})
		}
	} else {
		if name == "metrics" {
			tagTranslator := ""
			if db == "flow_log" {
				tagTranslator = fmt.Sprintf(tagItem.TagTranslator, "metrics_names", "metrics_values")
			} else {
				tagTranslator = fmt.Sprintf(tagItem.TagTranslator, "metrics_float_names", "metrics_float_values")
			}
			stmts = append(stmts, &SelectTag{Value: tagTranslator, Alias: selectTag})
		} else if name == "tag" && db == chCommon.DB_NAME_PROMETHEUS {
			tagTranslator, _, err := GetPrometheusAllTagTranslator(table)
			if err != nil {
				return nil, "", err
			}
			stmts = append(stmts, &SelectTag{Value: tagTranslator, Alias: selectTag})
		} else if slices.Contains(tag.AUTO_CUSTOM_TAG_NAMES, strings.Trim(selectTag, "`")) {
			autoTagMap := tagItem.TagTranslatorMap
			autoTagSlice := []string{}
			for autoTagKey, _ := range autoTagMap {
				autoTagSlice = append(autoTagSlice, autoTagKey)
			}
			sort.Strings(autoTagSlice)
			for _, autoTagKey := range autoTagSlice {
				if autoTagMap[autoTagKey] != "" {
					stmts = append(stmts, &SelectTag{Value: autoTagMap[autoTagKey], Alias: "`" + autoTagKey + "`"})
				} else {
					stmts = append(stmts, &SelectTag{Value: "`" + autoTagKey + "`"})
				}
			}
			// callback
			stmts = append(stmts, &SelectTag{Value: name})
		} else if tagItem.TagTranslator != "" {
			if name != "packet_batch" || table != "l4_packet" {
				stmts = append(stmts, &SelectTag{Value: tagItem.TagTranslator, Alias: selectTag})
			}
		} else if alias != "" {
			stmts = append(stmts, &SelectTag{Value: name, Alias: selectTag})
		} else {
			stmts = append(stmts, &SelectTag{Value: selectTag})
		}
	}
	return stmts, labelType, nil
}

func GetPrometheusSingleTagTranslator(tag, table string) (string, string, error) {
	labelType := ""
	TagTranslatorStr := ""
	nameNoPreffix := strings.TrimPrefix(tag, "tag.")
	metricID, ok := Prometheus.MetricNameToID[table]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", table)
		return "", "", common.NewError(common.RESOURCE_NOT_FOUND, errorMessage)
	}
	labelNameID, ok := Prometheus.LabelNameToID[nameNoPreffix]
	if !ok {
		errorMessage := fmt.Sprintf("%s not found", nameNoPreffix)
		return "", "", errors.New(errorMessage)
	}
	// Determine whether the tag is app_label or target_label
	isAppLabel := false
	if appLabels, ok := Prometheus.MetricAppLabelLayout[table]; ok {
		for _, appLabel := range appLabels {
			if appLabel.AppLabelName == nameNoPreffix {
				isAppLabel = true
				labelType = "app"
				TagTranslatorStr = fmt.Sprintf("dictGet(flow_tag.app_label_map, 'label_value', (%d, app_label_value_id_%d))", labelNameID, appLabel.appLabelColumnIndex)
				break
			}
		}
	}
	if !isAppLabel {
		labelType = "target"
		TagTranslatorStr = fmt.Sprintf("dictGet(flow_tag.target_label_map, 'label_value', (%d, %d, target_id))", metricID, labelNameID)
	}
	return TagTranslatorStr, labelType, nil
}

func GetPrometheusAllTagTranslator(table string) (string, string, error) {
	tagTranslatorStr := ""
	appLabelTranslatorStr := ""
	labelFastTranslatorSlice := []string{}
	if appLabels, ok := Prometheus.MetricAppLabelLayout[table]; ok {
		// appLabel
		appLabelTranslatorSlice := []string{}
		for _, appLabel := range appLabels {
			if labelNameID, ok := Prometheus.LabelNameToID[appLabel.AppLabelName]; ok {
				appLabelTranslator := fmt.Sprintf("'%s',dictGet(flow_tag.app_label_map, 'label_value', (%d, app_label_value_id_%d))", appLabel.AppLabelName, labelNameID, appLabel.appLabelColumnIndex)
				appLabelTranslatorSlice = append(appLabelTranslatorSlice, appLabelTranslator)
				labelFastTranslatorSlice = append(labelFastTranslatorSlice, fmt.Sprintf("app_label_value_id_%d", appLabel.appLabelColumnIndex))
			}
		}
		appLabelTranslatorStr = strings.Join(appLabelTranslatorSlice, ",")
	}

	// targetLabel
	targetLabelTranslatorStr := "CAST((splitByString(', ', dictGet(flow_tag.prometheus_target_label_layout_map, 'target_label_names', target_id)), splitByString(', ', dictGet(flow_tag.prometheus_target_label_layout_map, 'target_label_values', target_id))), 'Map(String, String)')"
	if appLabelTranslatorStr != "" {
		tagTranslatorStr = "toJSONString(mapUpdate(map(" + appLabelTranslatorStr + ")," + targetLabelTranslatorStr + "))"
	} else {
		tagTranslatorStr = "toJSONString(" + targetLabelTranslatorStr + ")"
	}
	labelFastTranslatorSlice = append(labelFastTranslatorSlice, "target_id")
	labelFastTranslatorStr := fmt.Sprintf("array(%s)", strings.Join(labelFastTranslatorSlice, ","))
	return tagTranslatorStr, labelFastTranslatorStr, nil
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
	Value string
	Alias string
	Flag  int
	Withs []view.Node
}

func (t *SelectTag) Format(m *view.Model) {
	if slices.Contains(tag.AUTO_CUSTOM_TAG_NAMES, strings.Trim(t.Value, "`")) {
		m.AddCallback(strings.Trim(t.Value, "`"), ColumnNameSwap([]interface{}{strings.Trim(t.Value, "`")}))
	} else {
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
}
