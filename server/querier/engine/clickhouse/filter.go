package clickhouse

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/xwb1989/sqlparser"
	"inet.af/netaddr"

	"github.com/metaflowys/metaflow/server/libs/utils"

	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/common"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/tag"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/view"
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
	tagItem, ok := tag.GetTag(t.Tag, db, table, "default")
	whereTag := t.Tag
	if strings.ToLower(op) == "like" || strings.ToLower(op) == "not like" {
		t.Value = strings.ReplaceAll(t.Value, "*", "%")
	}
	if !ok {
		preAsTag, ok := asTagMap[t.Tag]
		if ok {
			whereTag = preAsTag
			tagItem, ok = tag.GetTag(preAsTag, db, table, "default")
			if !ok {
				filter := ""
				switch preAsTag {
				case "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1":
					valueStr := strings.Trim(t.Value, "'")
					mac, err := net.ParseMAC(valueStr)
					if err != nil {
						return nil, err
					}
					valueUInt64 := utils.Mac2Uint64(mac)
					filter = fmt.Sprintf("%s %s %v", t.Tag, op, valueUInt64)
				case "tap_port":
					valueStr := strings.Trim(t.Value, "'")
					ip := net.ParseIP(valueStr)
					if ip != nil {
						ip4 := ip.To4()
						if ip4 != nil {
							ipUint32 := utils.IpToUint32(ip4)
							filter = fmt.Sprintf("%s %s %v", t.Tag, op, ipUint32)
						} else {
							return nil, errors.New("invalid ipv4 mac")
						}
					} else {
						valueStr = "00:00:" + valueStr
						mac, err := net.ParseMAC(valueStr)
						if err != nil {
							filter = fmt.Sprintf("%s %s %v", t.Tag, op, t.Value)
						} else {
							valueUInt64 := utils.Mac2Uint64(mac)
							filter = fmt.Sprintf("%s %s %v", t.Tag, op, valueUInt64)
						}
					}
				default:
					preAsTag = strings.Trim(preAsTag, "`")
					if strings.HasPrefix(preAsTag, "label.") {
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
							nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "label.")
							switch strings.ToLower(op) {
							case "regexp":
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, nameNoPreffix)
							case "not regexp":
								filter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, nameNoPreffix) + ")"
							case "not like":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "like", t.Value, nameNoPreffix) + ")"
							case "not in":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value, nameNoPreffix) + ")"
							case "!=":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value, nameNoPreffix) + ")"
							default:
								filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
							}
							return &view.Expr{Value: filter}, nil
						}
					} else if strings.HasPrefix(preAsTag, "tag.") || strings.HasPrefix(preAsTag, "attribute.") {
						if strings.HasPrefix(preAsTag, "tag.") {
							tagItem, ok = tag.GetTag("tag", db, table, "default")
						} else {
							tagItem, ok = tag.GetTag("attribute", db, table, "default")
						}
						if ok {
							nameNoPreffix := strings.TrimPrefix(preAsTag, "tag.")
							nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
							switch strings.ToLower(op) {
							case "regexp":
								filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", nameNoPreffix, t.Value)
							case "not regexp":
								filter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", nameNoPreffix, t.Value) + ")"
							case "not like":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "like", t.Value) + ")"
							case "not in":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "in", t.Value) + ")"
							case "!=":
								filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "=", t.Value) + ")"
							default:
								filter = fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, op, t.Value)
							}
							return &view.Expr{Value: filter}, nil
						}
					}
					switch strings.ToLower(op) {
					case "regexp":
						filter = fmt.Sprintf("match(%s,%s)", t.Tag, t.Value)
					case "not regexp":
						filter = fmt.Sprintf("NOT match(%s,%s)", t.Tag, t.Value)
					default:
						filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
					}
				}
				return &view.Expr{Value: filter}, nil
			}
		} else {
			filter := ""
			switch t.Tag {
			case "mac_0", "mac_1", "tunnel_tx_mac_0", "tunnel_tx_mac_1", "tunnel_rx_mac_0", "tunnel_rx_mac_1":
				valueStr := strings.Trim(t.Value, "'")
				mac, err := net.ParseMAC(valueStr)
				if err != nil {
					return nil, err
				}
				valueUInt64 := utils.Mac2Uint64(mac)
				filter = fmt.Sprintf("%s %s %v", t.Tag, op, valueUInt64)
			case "tap_port":
				valueStr := strings.Trim(t.Value, "'")
				ip := net.ParseIP(valueStr)
				if ip != nil {
					ip4 := ip.To4()
					if ip4 != nil {
						ipUint32 := utils.IpToUint32(ip4)
						filter = fmt.Sprintf("%s %s %v", t.Tag, op, ipUint32)
					} else {
						return nil, errors.New("invalid ipv4 mac")
					}
				} else {
					valueStr = "00:00:" + valueStr
					mac, err := net.ParseMAC(valueStr)
					if err != nil {
						filter = fmt.Sprintf("%s %s %v", t.Tag, op, t.Value)
					} else {
						valueUInt64 := utils.Mac2Uint64(mac)
						filter = fmt.Sprintf("%s %s %v", t.Tag, op, valueUInt64)
					}
				}
			default:
				t.Tag = strings.Trim(t.Tag, "`")
				if strings.HasPrefix(t.Tag, "label.") {
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
						nameNoPreffix := strings.TrimPrefix(nameNoSuffix, "label.")
						switch strings.ToLower(op) {
						case "regexp":
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, nameNoPreffix)
						case "not regexp":
							filter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, nameNoPreffix) + ")"
						case "not like":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "like", t.Value, nameNoPreffix) + ")"
						case "not in":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value, nameNoPreffix) + ")"
						case "!=":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value, nameNoPreffix) + ")"
						default:
							filter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, nameNoPreffix)
						}
						return &view.Expr{Value: filter}, nil
					}
				} else if strings.HasPrefix(t.Tag, "tag.") || strings.HasPrefix(t.Tag, "attribute.") {
					if strings.HasPrefix(t.Tag, "tag.") {
						tagItem, ok = tag.GetTag("tag", db, table, "default")
					} else {
						tagItem, ok = tag.GetTag("attribute", db, table, "default")
					}
					if ok {
						nameNoPreffix := strings.TrimPrefix(t.Tag, "tag.")
						nameNoPreffix = strings.TrimPrefix(nameNoPreffix, "attribute.")
						switch strings.ToLower(op) {
						case "regexp":
							filter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", nameNoPreffix, t.Value)
						case "not regexp":
							filter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", nameNoPreffix, t.Value) + ")"
						case "not like":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "like", t.Value) + ")"
						case "not in":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "in", t.Value) + ")"
						case "!=":
							filter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, "=", t.Value) + ")"
						default:
							filter = fmt.Sprintf(tagItem.WhereTranslator, nameNoPreffix, op, t.Value)
						}
						return &view.Expr{Value: filter}, nil
					}
				}
				switch strings.ToLower(op) {
				case "regexp":
					filter = fmt.Sprintf("match(%s,%s)", t.Tag, t.Value)
				case "not regexp":
					filter = fmt.Sprintf("NOT match(%s,%s)", t.Tag, t.Value)
				default:
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
			ipVersion := "0"
			if t.Value == "4" {
				ipVersion = "1"
			}
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, ipVersion)
		case "is_internet", "is_internet_0", "is_internet_1":
			if (t.Value == "0" && op == "=") || (t.Value == "1" && op == "!=") {
				newOP := "!="
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, newOP)
			} else {
				newOP := "="
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, newOP)
			}
		case "_id":
			valueStr := strings.Trim(t.Value, "'")
			valueInt, err := strconv.Atoi(valueStr)
			if err != nil {
				return nil, err
			}
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, valueInt)
		case "ip", "ip_0", "ip_1", "tunnel_tx_ip_0", "tunnel_tx_ip_1", "tunnel_rx_ip_0", "tunnel_rx_ip_1":
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
		case "pod_service_id", "pod_service_id_0", "pod_service_id_1":
			switch strings.ToLower(op) {
			case "not like":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "like", t.Value) + ")"
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
			}

		case "pod_ingress_id", "pod_ingress_id_0", "pod_ingress_id_1", "pod_ingress", "pod_ingress_0", "pod_ingress_1", "pod_service", "pod_service_0", "pod_service_1":
			switch strings.ToLower(op) {
			case "regexp":
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, "match", t.Value)
			case "not regexp":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value, "match", t.Value) + ")"
			case "not like":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "like", t.Value, "like", t.Value) + ")"
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value, "in", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value, "=", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, op, t.Value)
			}
		default:
			switch strings.ToLower(op) {
			case "regexp":
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value)
			case "not regexp":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value) + ")"
			case "not like":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "like", t.Value) + ")"
			case "not in":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "in", t.Value) + ")"
			case "!=":
				whereFilter = "not(" + fmt.Sprintf(tagItem.WhereTranslator, "=", t.Value) + ")"
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
			}
		}
	} else {
		filter := ""
		switch strings.ToLower(op) {
		case "regexp":
			filter = fmt.Sprintf("match(%s,%s)", t.Tag, t.Value)
		case "not regexp":
			filter = fmt.Sprintf("NOT match(%s,%s)", t.Tag, t.Value)
		default:
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
	if err != nil {
		return nil, err
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
	op, opType := view.GetOperator(expr.(*sqlparser.ComparisonExpr).Operator)
	if opType == view.OPERATOER_UNKNOWN {
		return nil, errors.New(fmt.Sprintf("opeartor: %s not support", expr.(*sqlparser.ComparisonExpr).Operator))
	}
	right := view.Expr{Value: f.Value}
	w.withs = append(w.withs, f.Function.GetWiths()...)
	return &view.BinaryExpr{Left: f.Function, Right: &right, Op: op}, nil
}
