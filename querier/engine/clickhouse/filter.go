package clickhouse

import (
	"fmt"
	"inet.af/netaddr"
	"strconv"
	"strings"

	"github.com/xwb1989/sqlparser"

	"metaflow/querier/engine/clickhouse/tag"
	"metaflow/querier/engine/clickhouse/view"
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

func GetWhere(name, value string) WhereStatement {
	switch name {
	case "`time`":
		return &TimeTag{Value: value}
	default:
		return &WhereTag{Tag: name, Value: value}
	}
}

type WhereStatement interface {
	Trans(sqlparser.Expr, *Where, map[string]string) (view.Node, error)
}

type WhereTag struct {
	Tag   string
	Value string
}

var OperatorMap = map[string]string{
	"in":     " OR ",
	"not in": " AND ",
}

func (t *WhereTag) Trans(expr sqlparser.Expr, w *Where, asTagMap map[string]string) (view.Node, error) {
	op := expr.(*sqlparser.ComparisonExpr).Operator
	tagItem, ok := tag.GetTag(t.Tag)
	if !ok {
		preAsTag, ok := asTagMap[t.Tag]
		if ok {
			tagItem, ok = tag.GetTag(preAsTag)
			if !ok {
				filter := fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
				return &view.Expr{Value: filter}, nil
			}
		} else {
			filter := fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
			return &view.Expr{Value: filter}, nil
		}
	}
	whereFilter := tagItem.WhereTranslator
	if whereFilter != "" {
		switch t.Tag {
		case "ip", "ip_0", "ip_1":
			ipValues := strings.TrimLeft(t.Value, "(")
			ipValues = strings.TrimRight(ipValues, ")")
			ipSlice := strings.Split(ipValues, ",")
			ip4s := []string{}
			ip6s := []string{}
			ip4WhereFilter := ""
			ip6WhereFilter := ""
			for _, ipValue := range ipSlice {
				ipValue = strings.Trim(ipValue, " ")
				ipValue = strings.Trim(ipValue, "'")
				ip, err := netaddr.ParseIP(ipValue)
				if err != nil {
					log.Error(err)
					return nil, err
				} else {
					if ip.Is4() {
						ip4s = append(ip4s, fmt.Sprintf("toIPv4('%s')", ipValue))
					} else {
						ip6s = append(ip4s, fmt.Sprintf("toIPv4('%s')", ipValue))
					}
				}
			}
			if len(ip4s) > 0 {
				ip4sStr := strings.Join(ip4s, ",")
				ip4WhereFilter = fmt.Sprintf(tagItem.WhereTranslator, "1", "4", op, "("+ip4sStr+")")
			}
			if len(ip6s) > 0 {
				ip6sStr := strings.Join(ip6s, ",")
				ip6WhereFilter = fmt.Sprintf(tagItem.WhereTranslator, "0", "6", op, "("+ip6sStr+")")
			}
			ipFilterSlice := []string{}
			if ip4WhereFilter != "" {
				ipFilterSlice = append(ipFilterSlice, ip4WhereFilter)
			}
			if ip6WhereFilter != "" {
				ipFilterSlice = append(ipFilterSlice, ip6WhereFilter)
			}
			whereFilter = strings.Join(ipFilterSlice, OperatorMap[op])
		case "include_service":
			isKeyService := "0"
			if t.Value == "1" {
				isKeyService = "1"
			}
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, isKeyService)
		default:
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
		}
	} else {
		return &view.Expr{Value: "(1=1)"}, nil
	}
	return &view.Expr{Value: "(" + whereFilter + ")"}, nil
}

type TimeTag struct {
	Value string
}

func (t *TimeTag) Trans(expr sqlparser.Expr, w *Where, asTagMap map[string]string) (view.Node, error) {
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
