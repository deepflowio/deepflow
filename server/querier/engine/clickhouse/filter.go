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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
	"github.com/xwb1989/sqlparser"
	"inet.af/netaddr"
)

type Where struct {
	filter *view.Filters
	withs  []view.Node
	time   *view.Time
}

func (w *Where) Format(m *view.Model) {
	w.filter.Withs = w.withs
	if !w.filter.IsNull() {
		m.AddFilter(w.filter)
	}
}

type Having struct {
	Where
}

func (h *Having) Format(m *view.Model) {
	h.filter.Withs = h.withs
	if !h.filter.IsNull() {
		m.AddHaving(h.filter)
	}
}

func GetWhere(name, value string) WhereStatement {
	switch name {
	case "time":
		return &TimeTag{Value: value}
	default:
		return &WhereTag{Tag: name, Value: value}
	}
}

type WhereStatement interface {
	Trans(sqlparser.Expr, *Where, map[string]string, string, string) (view.Node, error)
}

type WhereTag struct {
	Tag   string
	Value string
}

func (t *WhereTag) Trans(expr sqlparser.Expr, w *Where, asTagMap map[string]string, db, table string) (view.Node, error) {
	op := expr.(*sqlparser.ComparisonExpr).Operator
	tagItem, ok := tag.GetTag(strings.Trim(t.Tag, "`"), db, table, "default")
	whereTag := t.Tag
	if strings.ToLower(op) == "like" || strings.ToLower(op) == "not like" {
		t.Value = strings.ReplaceAll(t.Value, "*", "%")
		if strings.ToLower(op) == "like" {
			op = "ilike"
		} else {
			op = "not ilike"
		}
	} else if strings.ToLower(op) == "regexp" || strings.ToLower(op) == "not regexp" {
		if strings.ToLower(op) == "regexp" {
			op = "match"
		} else {
			op = "not match"
		}
	}
	if !ok {
		preAsTag, ok := asTagMap[t.Tag]
		if ok {
			whereTag = preAsTag
			tagItem, ok = tag.GetTag(strings.Trim(preAsTag, "`"), db, table, "default")
			if !ok {
				filter := ""
				switch preAsTag {
				case "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1":
					macValue := strings.TrimLeft(t.Value, "(")
					macValue = strings.TrimRight(macValue, ")")
					macSlice := strings.Split(macValue, ",")
					macs := []string{}
					for _, valueStr := range macSlice {
						valueStr = strings.TrimSpace(valueStr)
						valueStr = strings.Trim(valueStr, "'")
						mac, err := net.ParseMAC(valueStr)
						if err != nil {
							return nil, err
						}
						valueUInt64 := utils.Mac2Uint64(mac)
						macs = append(macs, fmt.Sprintf("'%v'", valueUInt64))
					}
					if len(macs) != 0 {
						macsStr := strings.Join(macs, ",")
						if strings.ToLower(op) == "in" || strings.ToLower(op) == "not in" {
							macsStr = "(" + macsStr + ")"
						}
						filter = fmt.Sprintf("%s %s %s", t.Tag, op, macsStr)
					}
				case "tap_port":
					macValue := strings.TrimLeft(t.Value, "(")
					macValue = strings.TrimRight(macValue, ")")
					macSlice := strings.Split(macValue, ",")
					macs := []string{}
					for _, valueStr := range macSlice {
						valueStr = strings.TrimSpace(valueStr)
						valueStr = strings.Trim(valueStr, "'")
						ip := net.ParseIP(valueStr)
						if ip != nil {
							ip4 := ip.To4()
							if ip4 != nil {
								ipUint32 := utils.IpToUint32(ip4)
								macs = append(macs, fmt.Sprintf("'%v'", ipUint32))
							} else {
								return nil, errors.New(fmt.Sprintf("invalid ipv4 mac: %s", valueStr))
							}
						} else {
							macValueStr := "00:00:" + valueStr
							mac, err := net.ParseMAC(macValueStr)
							if err != nil {
								macs = append(macs, fmt.Sprintf("'%v'", valueStr))
							} else {
								valueUInt64 := utils.Mac2Uint64(mac)
								macs = append(macs, fmt.Sprintf("'%v'", valueUInt64))
							}
						}
					}
					if len(macs) != 0 {
						macsStr := strings.Join(macs, ",")
						if strings.ToLower(op) == "in" || strings.ToLower(op) == "not in" {
							macsStr = "(" + macsStr + ")"
						}
						filter = fmt.Sprintf("%s %s %s", t.Tag, op, macsStr)
					}
				default:
					preAsTag = strings.Trim(preAsTag, "`")
					if strings.HasPrefix(preAsTag, "k8s.label.") {
						if strings.HasSuffix(preAsTag, "_0") {
							tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
						} else if strings.HasSuffix(preAsTag, "_1") {
							tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
						} else {
							tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
						}
						if ok {
							nameNoSuffix := strings.TrimSuffix(preAsTag, "_0")
							nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
							nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.label.")
							if strings.Contains(op, "match") {
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix)
							} else {
								filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
							}
							return &view.Expr{Value: filter}, nil
						}
					} else if strings.HasPrefix(preAsTag, "cloud.tag.") {
						if strings.HasSuffix(preAsTag, "_0") {
							tagItem, ok = tag.GetTag("cloud_tag_0", db, table, "default")
						} else if strings.HasSuffix(preAsTag, "_1") {
							tagItem, ok = tag.GetTag("cloud_tag_1", db, table, "default")
						} else {
							tagItem, ok = tag.GetTag("cloud_tag", db, table, "default")
						}
						if ok {
							nameNoSuffix := strings.TrimSuffix(preAsTag, "_0")
							nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
							nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "cloud.tag.")
							if strings.Contains(op, "match") {
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix, op, t.Value, nameNoPreffix)
							} else {
								filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix, op, t.Value, nameNoPreffix)
							}
							return &view.Expr{Value: filter}, nil
						}
					} else if strings.HasPrefix(preAsTag, "os.app.") {
						if strings.HasSuffix(preAsTag, "_0") {
							tagItem, ok = tag.GetTag("os_app_0", db, table, "default")
						} else if strings.HasSuffix(preAsTag, "_1") {
							tagItem, ok = tag.GetTag("os_app_1", db, table, "default")
						} else {
							tagItem, ok = tag.GetTag("os_app", db, table, "default")
						}
						if ok {
							nameNoSuffix := strings.TrimSuffix(preAsTag, "_0")
							nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
							nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "os.app.")
							if strings.Contains(op, "match") {
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix)
							} else {
								filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
							}
							return &view.Expr{Value: filter}, nil
						}
					} else if strings.HasPrefix(preAsTag, "tag.") || strings.HasPrefix(preAsTag, "attribute.") {
						if strings.HasPrefix(preAsTag, "tag.") {
							tagItem, ok = tag.GetTag("tag.", db, table, "default")
						} else {
							tagItem, ok = tag.GetTag("attribute.", db, table, "default")
						}
						if ok {
							nameNoPreffix := strings.TrimPrefix(preAsTag, "tag.")
							nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
							if strings.Contains(op, "match") {
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, nameNoPreffix, t.Value)
							} else {
								filter = fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, op, t.Value)
							}
							return &view.Expr{Value: filter}, nil
						}
					}
					if strings.Contains(op, "match") {
						filter = fmt.Sprintf("%s(%s,%s)", op, t.Tag, t.Value)
					} else {
						filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
					}
				}
				return &view.Expr{Value: filter}, nil
			}
		} else {
			filter := ""
			switch t.Tag {
			case "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1":
				macValue := strings.TrimLeft(t.Value, "(")
				macValue = strings.TrimRight(macValue, ")")
				macSlice := strings.Split(macValue, ",")
				macs := []string{}
				for _, valueStr := range macSlice {
					valueStr = strings.TrimSpace(valueStr)
					valueStr = strings.Trim(valueStr, "'")
					mac, err := net.ParseMAC(valueStr)
					if err != nil {
						return nil, err
					}
					valueUInt64 := utils.Mac2Uint64(mac)
					macs = append(macs, fmt.Sprintf("'%v'", valueUInt64))
				}
				if len(macs) != 0 {
					macsStr := strings.Join(macs, ",")
					if strings.ToLower(op) == "in" || strings.ToLower(op) == "not in" {
						macsStr = "(" + macsStr + ")"
					}
					filter = fmt.Sprintf("%s %s %s", t.Tag, op, macsStr)
				}
			case "tap_port":
				macValue := strings.TrimLeft(t.Value, "(")
				macValue = strings.TrimRight(macValue, ")")
				macSlice := strings.Split(macValue, ",")
				macs := []string{}
				for _, valueStr := range macSlice {
					valueStr = strings.TrimSpace(valueStr)
					valueStr = strings.Trim(valueStr, "'")
					ip := net.ParseIP(valueStr)
					if ip != nil {
						ip4 := ip.To4()
						if ip4 != nil {
							ipUint32 := utils.IpToUint32(ip4)
							macs = append(macs, fmt.Sprintf("'%v'", ipUint32))
						} else {
							return nil, errors.New(fmt.Sprintf("invalid ipv4 mac: %s", valueStr))
						}
					} else {
						macValueStr := "00:00:" + valueStr
						mac, err := net.ParseMAC(macValueStr)
						if err != nil {
							macs = append(macs, fmt.Sprintf("'%v'", valueStr))
						} else {
							valueUInt64 := utils.Mac2Uint64(mac)
							macs = append(macs, fmt.Sprintf("'%v'", valueUInt64))
						}
					}
				}
				if len(macs) != 0 {
					macsStr := strings.Join(macs, ",")
					if strings.ToLower(op) == "in" || strings.ToLower(op) == "not in" {
						macsStr = "(" + macsStr + ")"
					}
					filter = fmt.Sprintf("%s %s %s", t.Tag, op, macsStr)
				}
			default:
				t.Tag = strings.Trim(t.Tag, "`")
				if strings.HasPrefix(t.Tag, "k8s.label.") {
					if strings.HasSuffix(t.Tag, "_0") {
						tagItem, ok = tag.GetTag("k8s_label_0", db, table, "default")
					} else if strings.HasSuffix(t.Tag, "_1") {
						tagItem, ok = tag.GetTag("k8s_label_1", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("k8s_label", db, table, "default")
					}
					if ok {
						nameNoSuffix := strings.TrimSuffix(t.Tag, "_0")
						nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
						nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "k8s.label.")
						if strings.Contains(op, "match") {
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix)
						} else {
							filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
						}
						return &view.Expr{Value: filter}, nil
					}
				} else if strings.HasPrefix(t.Tag, "cloud.tag.") {
					if strings.HasSuffix(t.Tag, "_0") {
						tagItem, ok = tag.GetTag("cloud_tag_0", db, table, "default")
					} else if strings.HasSuffix(t.Tag, "_1") {
						tagItem, ok = tag.GetTag("cloud_tag_1", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("cloud_tag", db, table, "default")
					}
					if ok {
						nameNoSuffix := strings.TrimSuffix(t.Tag, "_0")
						nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
						nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "cloud.tag.")
						if strings.Contains(op, "match") {
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix, op, t.Value, nameNoPreffix)
						} else {
							filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix, op, t.Value, nameNoPreffix)
						}
						return &view.Expr{Value: filter}, nil
					}
				} else if strings.HasPrefix(t.Tag, "os.app.") {
					if strings.HasSuffix(t.Tag, "_0") {
						tagItem, ok = tag.GetTag("os_app_0", db, table, "default")
					} else if strings.HasSuffix(t.Tag, "_1") {
						tagItem, ok = tag.GetTag("os_app_1", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("os_app", db, table, "default")
					}
					if ok {
						nameNoSuffix := strings.TrimSuffix(t.Tag, "_0")
						nameNoSuffix = strings.TrimSuffix(nameNoSuffix, "_1")
						nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "os.app.")
						if strings.Contains(op, "match") {
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, nameNoPreffix)
						} else {
							filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
						}
						return &view.Expr{Value: filter}, nil
					}
				} else if strings.HasPrefix(t.Tag, "tag.") || strings.HasPrefix(t.Tag, "attribute.") {
					if strings.HasPrefix(t.Tag, "tag.") {
						tagItem, ok = tag.GetTag("tag.", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("attribute.", db, table, "default")
					}
					if ok {
						nameNoPreffix := strings.TrimPrefix(t.Tag, "tag.")
						nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
						if strings.Contains(op, "match") {
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, nameNoPreffix, t.Value)
						} else {
							filter = fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, op, t.Value)
						}
						return &view.Expr{Value: filter}, nil
					}
				} else if strings.HasPrefix(t.Tag, "Enum(") {
					t.Tag = strings.TrimPrefix(t.Tag, "Enum(")
					t.Tag = strings.TrimSuffix(t.Tag, ")")
					tagItem, ok = tag.GetTag(t.Tag, db, table, "enum")
					if ok {
						if strings.Contains(op, "match") {
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value)
						} else {
							filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
						}
						return &view.Expr{Value: filter}, nil
					}
				}
				if strings.Contains(op, "match") {
					filter = fmt.Sprintf("%s(%s,%s)", op, t.Tag, t.Value)
				} else {
					filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
				}
			}
			return &view.Expr{Value: filter}, nil
		}
	}
	whereFilter := tagItem.WhereTranslator
	if whereFilter != "" {
		switch whereTag {
		case "ip_version":
			versionValue := strings.TrimLeft(t.Value, "(")
			versionValue = strings.TrimRight(versionValue, ")")
			versionSlice := strings.Split(versionValue, ",")
			versions := []string{}
			for _, valueStr := range versionSlice {
				ipVersion := "0"
				if valueStr == "4" {
					ipVersion = "1"
				}
				versions = append(versions, ipVersion)
			}
			if len(versions) != 0 {
				versionsStr := strings.Join(versions, ",")
				if strings.ToLower(op) == "in" || strings.ToLower(op) == "not in" {
					versionsStr = "(" + versionsStr + ")"
				}
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, versionsStr)
			}
		case "is_internet", "is_internet_0", "is_internet_1":
			internetValue := strings.TrimLeft(t.Value, "(")
			internetValue = strings.TrimRight(internetValue, ")")
			internetSlice := strings.Split(internetValue, ",")
			hasTrue := false
			hasFalse := false
			newOP := ""
			for _, valueStr := range internetSlice {
				if valueStr == "1" || valueStr == "'1'" {
					hasTrue = true
				} else {
					hasFalse = true
				}
			}
			if hasTrue == true && hasFalse == true {
				whereFilter = "1=1"
			} else if hasTrue == true {
				if op == "=" || strings.ToLower(op) == "in" {
					newOP = "="
				} else {
					newOP = "!="
				}
			} else {
				if op == "=" || strings.ToLower(op) == "in" {
					newOP = "!="
				} else {
					newOP = "="
				}
			}
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, newOP)
		case "_id":
			idValue := strings.TrimLeft(t.Value, "(")
			idValue = strings.TrimRight(idValue, ")")
			idSlice := strings.Split(idValue, ",")
			whereFilters := []string{}
			for _, valueStr := range idSlice {
				valueStr = strings.Trim(t.Value, "'")
				valueInt, err := strconv.Atoi(valueStr)
				if err != nil {
					return nil, err
				}
				idFilter := fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, valueInt)
				whereFilters = append(whereFilters, "("+idFilter+")")
			}
			if len(whereFilters) != 0 {
				equalFilter := "(" + strings.Join(whereFilters, " OR ") + ")"
				switch strings.ToLower(op) {
				case "not in":
					whereFilter = "not(" + equalFilter + ")"
				case "!=":
					whereFilter = "not(" + equalFilter + ")"
				default:
					whereFilter = equalFilter
				}
			}

		case "ip", "ip_0", "ip_1", "tunnel_tx_ip_0", "tunnel_tx_ip_1", "tunnel_rx_ip_0", "tunnel_rx_ip_1", "nat_real_ip", "nat_real_ip_0", "nat_real_ip_1":
			equalFilter := ""
			ipValues := strings.TrimLeft(t.Value, "(")
			ipValues = strings.TrimRight(ipValues, ")")
			ipSlice := strings.Split(ipValues, ",")
			ipOp := strings.ToLower(op)
			ipsFilter := ""
			cidrIPs := []string{}
			cidrFilters := []string{}
			ips := []string{}
			for _, ipValue := range ipSlice {
				ipValue = strings.Trim(ipValue, " ")
				if strings.Contains(ipValue, "/") {
					cidrIPs = append(cidrIPs, ipValue)
				} else {
					ips = append(ips, common.IPFilterStringToHex(ipValue))
				}
			}
			for _, cidrIP := range cidrIPs {
				cidrIP = strings.Trim(cidrIP, "'")
				cidr, err := netaddr.ParseIPPrefix(cidrIP)
				if err != nil {
					return nil, err
				}
				minIP := common.IPFilterStringToHex("'" + cidr.Masked().Range().From().String() + "'")
				maxIP := common.IPFilterStringToHex("'" + cidr.Masked().Range().To().String() + "'")
				cidrFilter := ""
				if ipOp == ">=" {
					cidrFilter = fmt.Sprintf(tagItem.WhereTranslator, ipOp, maxIP)
				} else if ipOp == "<=" {
					cidrFilter = fmt.Sprintf(tagItem.WhereTranslator, ipOp, minIP)
				} else {
					cidrFilter = "(" + fmt.Sprintf(tagItem.WhereTranslator, ">=", minIP) + " AND " + fmt.Sprintf(tagItem.WhereTranslator, "<=", maxIP) + ")"
				}
				cidrFilters = append(cidrFilters, cidrFilter)
			}
			cidrFilterStr := ""
			if len(cidrFilters) != 0 {
				cidrFilterStr = "(" + strings.Join(cidrFilters, " OR ") + ")"
			}
			if len(ips) != 0 {
				if ipOp == ">=" || ipOp == "<=" {
					ipFilters := []string{}
					for _, ip := range ips {
						ipFilters = append(ipFilters, fmt.Sprintf(tagItem.WhereTranslator, ipOp, ip))
					}
					ipsFilter = "(" + strings.Join(ipFilters, " OR ") + ")"
				} else {
					ipsStr := strings.Join(ips, ",")
					equalOP := ""
					if ipOp == "in" || ipOp == "not in" {
						ipsStr = "(" + ipsStr + ")"
						equalOP = "in"
					} else {
						equalOP = "="
					}
					ipsFilter = "(" + fmt.Sprintf(tagItem.WhereTranslator, equalOP, ipsStr) + ")"
				}
			}
			finalFilters := []string{}
			if cidrFilterStr != "" {
				finalFilters = append(finalFilters, cidrFilterStr)
			}
			if ipsFilter != "" {
				finalFilters = append(finalFilters, ipsFilter)
			}
			equalFilter = "(" + strings.Join(finalFilters, " OR ") + ")"
			switch ipOp {
			case "not in":
				whereFilter = "not(" + equalFilter + ")"
			case "!=":
				whereFilter = "not(" + equalFilter + ")"
			default:
				whereFilter = equalFilter
			}
		case "pod_service_id", "pod_service_id_0", "pod_service_id_1", "natgw_id", "natgw_id_0", "natgw_id_1", "natgw", "natgw_0", "natgw_1",
			"lb_id", "lb_id_0", "lb_id_1", "lb", "lb_0", "lb_1", "lb_listener_id", "lb_listener_id_0", "lb_listener_id_1", "lb_listener", "lb_listener_0", "lb_listener_1":
			switch strings.ToLower(op) {
			case "not match":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value) + ")"
			case "not ilike":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "ilike", t.Value) + ")"
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
			}
		case "pod_ingress_id", "pod_ingress_id_0", "pod_ingress_id_1", "pod_ingress", "pod_ingress_0", "pod_ingress_1",
			"pod_service", "pod_service_0", "pod_service_1":
			switch strings.ToLower(op) {
			case "not match":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, "match", t.Value) + ")"
			case "not ilike":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "ilike", t.Value, "ilike", t.Value) + ")"
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value, "in", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value, "=", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, op, t.Value)
			}
		case "resource_gl0", "resource_gl0_0", "resource_gl0_1", "resource_gl1", "resource_gl1_0", "resource_gl1_1",
			"resource_gl2", "resource_gl2_0", "resource_gl2_1", "resource_gl0_id", "resource_gl0_id_0", "resource_gl0_id_1",
			"resource_gl1_id", "resource_gl1_id_0", "resource_gl1_id_1", "resource_gl2_id", "resource_gl2_id_0", "resource_gl2_id_1",
			"auto_instance", "auto_instance_0", "auto_instance_1", "auto_instance_id", "auto_instance_id_0", "auto_instance_id_1",
			"auto_service", "auto_service_0", "auto_service_1", "auto_service_id", "auto_service_id_0", "auto_service_id_1":
			if strings.Contains(op, "match") {
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value, op, t.Value)
			} else {
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, op, t.Value)
			}
		case "ips", "subnets_id", "subnets":
			t.Value = strings.TrimPrefix(t.Value, "(")
			t.Value = strings.TrimSuffix(t.Value, ")")
			switch strings.ToLower(op) {
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "hasAny", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "hasAny", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, "hasAny", t.Value)
			}
		case "acl_gids":
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, t.Value)
		default:
			if strings.Contains(op, "match") {
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, op, t.Value)
			} else {
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
			}
		}
	} else {
		filter := ""
		if strings.Contains(op, "match") {
			filter = fmt.Sprintf("%s(%s,%s)", op, t.Tag, t.Value)
		} else {
			filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
		}
		return &view.Expr{Value: filter}, nil
	}
	return &view.Expr{Value: "(" + whereFilter + ")"}, nil
}

type TimeTag struct {
	Value string
}

func (t *TimeTag) Trans(expr sqlparser.Expr, w *Where, asTagMap map[string]string, db, table string) (view.Node, error) {
	compareExpr := expr.(*sqlparser.ComparisonExpr)
	time, err := strconv.ParseInt(t.Value, 10, 64)
	if err == nil {
	} else {
		timeExpr, err := govaluate.NewEvaluableExpression(t.Value)
		if err != nil {
			return nil, err
		}
		timeValue, err := timeExpr.Evaluate(nil)
		if err != nil {
			return nil, err
		}
		time = int64(timeValue.(float64))
	}
	if compareExpr.Operator == ">=" {
		w.time.AddTimeStart(time)
	} else if compareExpr.Operator == "<=" {
		w.time.AddTimeEnd(time)
	}
	return &view.Expr{Value: sqlparser.String(compareExpr)}, nil
}

type WhereFunction struct {
	Function view.Node
	Value    string
}

func (f *WhereFunction) Trans(expr sqlparser.Expr, w *Where, asTagMap map[string]string, db, table string) (view.Node, error) {
	opName := expr.(*sqlparser.ComparisonExpr).Operator
	op, opType := view.GetOperator(expr.(*sqlparser.ComparisonExpr).Operator)
	right := view.Expr{Value: ""}
	if opType == view.OPERATOER_UNKNOWN {
		return nil, errors.New(fmt.Sprintf("opeartor: %s not support", expr.(*sqlparser.ComparisonExpr).Operator))
	}
	function := strings.Trim(f.Function.ToString(), "`")
	if strings.HasPrefix(function, "Enum(") {
		var isIntEnum = true
		tagName := strings.TrimPrefix(function, "Enum(")
		tagName = strings.TrimSuffix(tagName, ")")
		tagName = strings.Trim(tagName, "`")
		tagEnum := strings.TrimSuffix(tagName, "_0")
		tagEnum = strings.TrimSuffix(tagEnum, "_1")
		tagDescription, ok := tag.TAG_DESCRIPTIONS[tag.TagDescriptionKey{
			DB: db, Table: table, TagName: tagEnum,
		}]
		if !ok {
			return nil, errors.New(fmt.Sprintf("no tag %s in %s.%s", tagName, db, table))
		}
		_, isStringEnumOK := tag.TAG_STRING_ENUMS[tagDescription.EnumFile]
		if isStringEnumOK {
			isIntEnum = false
		}
		tagItem, ok := tag.GetTag(tagName, db, table, "enum")
		if !ok {
			right = view.Expr{Value: f.Value}
		} else {
			whereFilter := tagItem.WhereTranslator
			if strings.ToLower(opName) == "like" || strings.ToLower(opName) == "not like" {
				f.Value = strings.ReplaceAll(f.Value, "*", "%")
				if strings.ToLower(opName) == "like" {
					opName = "ilike"
				} else {
					opName = "not ilike"
				}
			} else if strings.ToLower(opName) == "regexp" || strings.ToLower(opName) == "not regexp" {
				if strings.ToLower(opName) == "regexp" {
					opName = "match"
				} else {
					opName = "not match"
				}
			}
			enumFileName := strings.TrimSuffix(tagDescription.EnumFile, "."+config.Cfg.Language)
			switch strings.ToLower(expr.(*sqlparser.ComparisonExpr).Operator) {
			case "=":
				//when enum function operator is '=' , add 'or tag = xxx'
				if isIntEnum {
					intValue, err := strconv.Atoi(strings.Trim(f.Value, "'"))
					if err == nil {
						// when value type is int, add toUInt64() function
						whereFilter = fmt.Sprintf(tagItem.WhereTranslator, "=", f.Value, enumFileName) + " OR " + tagName + " = " + "toUInt64(" + strconv.Itoa(intValue) + ")"
					} else {
						whereFilter = fmt.Sprintf(tagItem.WhereTranslator, "=", f.Value, enumFileName)
					}
				} else {
					whereFilter = fmt.Sprintf(tagItem.WhereTranslator, "=", f.Value, enumFileName) + " OR " + tagName + " = " + f.Value
				}
			case "!=":
				//when enum function operator is '!=', add 'and tag != xxx'
				if isIntEnum {
					intValue, err := strconv.Atoi(strings.Trim(f.Value, "'"))
					if err == nil {
						// when value type is int, add toUInt64() function
						whereFilter = fmt.Sprintf(tagItem.WhereTranslator, opName, f.Value, enumFileName) + " AND " + tagName + " != " + "toUInt64(" + strconv.Itoa(intValue) + ")"
					} else {
						whereFilter = fmt.Sprintf(tagItem.WhereTranslator, opName, f.Value, enumFileName)
					}
				} else {
					whereFilter = fmt.Sprintf(tagItem.WhereTranslator, "=", f.Value, enumFileName) + " AND " + tagName + " != " + f.Value
				}
			default:
				if strings.Contains(opName, "match") {
					whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, opName, f.Value, enumFileName)
				} else {
					whereFilter = fmt.Sprintf(tagItem.WhereTranslator, opName, f.Value, enumFileName)
				}
			}
			return &view.Expr{Value: "(" + whereFilter + ")"}, nil
		}
	} else {
		right = view.Expr{Value: f.Value}
	}
	w.withs = append(w.withs, f.Function.GetWiths()...)
	return &view.BinaryExpr{Left: f.Function, Right: &right, Op: op}, nil
}
