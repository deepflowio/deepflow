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

package clickhouse

import (
	"fmt"
	"strings"

	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/view"
)

func GetGroup(name string, asTagMap map[string]string, db, table string) (Statement, error) {
	if asTagMap[name] == "time" {
		return nil, nil
	}
	var stmt Statement
	tag, ok := tag.GetTag(name, db, table, "default")
	if ok {
		if tag.TagTranslator != "" {
			stmt = &GroupTag{Value: tag.TagTranslator, Alias: name}
		} else {
			stmt = &GroupTag{Value: name}
		}
	} else {
		stmt = &GroupTag{Value: name}
	}
	return stmt, nil
}

func GetNotNullFilter(name string, asTagMap map[string]string, db, table string) (view.Node, bool) {
	tagItem, ok := tag.GetTag(name, db, table, "default")
	if !ok {
		preAsTag, ok := asTagMap[name]
		if ok {
			tagItem, ok = tag.GetTag(preAsTag, db, table, "default")
			if !ok {
				preAsTag := strings.Trim(preAsTag, "`")
				if strings.HasPrefix(preAsTag, "label.") {
					if strings.HasSuffix(preAsTag, "_0") {
						tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
					} else if strings.HasSuffix(preAsTag, "_1") {
						tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
					}
					filter := tagItem.NotNullFilter
					return &view.Expr{Value: "(" + filter + ")"}, true
				}
				return &view.Expr{}, false
			}
			filter := tagItem.NotNullFilter
			if filter == "" {
				return &view.Expr{}, false
			}
			return &view.Expr{Value: "(" + filter + ")"}, true
		} else {
			name := strings.Trim(name, "`")
			if strings.HasPrefix(name, "label.") {
				if strings.HasSuffix(name, "_0") {
					tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
				} else if strings.HasSuffix(name, "_1") {
					tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
				} else {
					tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
				}
				filter := tagItem.NotNullFilter
				return &view.Expr{Value: "(" + filter + ")"}, true
			}
			return &view.Expr{}, false
		}
	}
	if tagItem.NotNullFilter == "" {
		return &view.Expr{}, false
	}
	filter := tagItem.NotNullFilter
	return &view.Expr{Value: "(" + filter + ")"}, true
}

func FormatInnerTime(m *view.Model) {
	if m.DB == "flow_metrics" && m.Time.Interval == 0 && m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED && m.HasAggFunc == true {
		withValue := fmt.Sprintf(
			"toStartOfInterval(time, toIntervalSecond(%d))",
			m.Time.DatasourceInterval,
		)
		withAlias := "_time"
		withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
		m.AddTag(&view.Tag{Value: withAlias, Withs: withs, Flag: view.NODE_FLAG_METRICS_INNER})
		m.AddGroup(&view.Group{Value: withAlias, Flag: view.GROUP_FLAG_METRICS_INNTER})
	}
}

type GroupTag struct {
	Value string
	Alias string
	Withs []view.Node
}

func (g *GroupTag) Format(m *view.Model) {
	if len(g.Withs) == 0 {
		m.AddGroup(&view.Group{Value: g.Value, Alias: g.Alias})
	} else {
		m.AddGroup(&view.Group{Value: g.Value, Withs: g.Withs})
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		ip4Suffix := "ip4" + suffix
		ip6Suffix := "ip6" + suffix
		for _, resourceName := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
			resourceIDSuffix := resourceName + "_id" + suffix
			resourceTypeSuffix := resourceName + "_type" + suffix
			if g.Alias == resourceName+suffix {
				ipTag := fmt.Sprintf("multiIf(%s=0 and is_ipv4=1,IPv4NumToString(%s), %s=0 and is_ipv4=0,IPv6NumToString(%s),%s!=0 and is_ipv4=1,'0.0.0.0','::')", resourceIDSuffix, ip4Suffix, resourceIDSuffix, ip6Suffix, resourceIDSuffix)
				subnetIDSuffix := "subnet_id" + suffix
				subnetTag := fmt.Sprintf("if(%s=0,%s,0)", resourceIDSuffix, subnetIDSuffix)
				m.AddTag(&view.Tag{Value: ipTag, Alias: "ip" + suffix})
				m.AddTag(&view.Tag{Value: subnetTag, Alias: subnetIDSuffix})
				m.AddTag(&view.Tag{Value: resourceTypeSuffix})
				m.AddGroup(&view.Group{Value: "ip" + suffix})
				m.AddGroup(&view.Group{Value: subnetIDSuffix})
				m.AddGroup(&view.Group{Value: resourceTypeSuffix})
			}
		}
		// internet增加epc分组
		internetSuffix := "is_internet" + suffix
		epcSuffix := "l3_epc_id" + suffix
		if g.Alias == internetSuffix {
			m.AddGroup(&view.Group{Value: epcSuffix})
		}
	}
}
