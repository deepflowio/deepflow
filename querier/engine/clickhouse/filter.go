package clickhouse

import (
	"errors"
	"fmt"
	"github.com/xwb1989/sqlparser"
	"net"
	"strconv"
	"strings"

	"gitlab.yunshan.net/yunshan/droplet-libs/utils"

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
	case "`time`":
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
	if !ok {
		preAsTag, ok := asTagMap["`"+t.Tag+"`"]
		if ok {
			tagItem, ok = tag.GetTag(preAsTag, db, table, "default")
			if !ok {
				filter := ""
				if strings.ToLower(op) == "regexp" {
					filter = fmt.Sprintf("match(%s,%s)", t.Tag, t.Value)
				} else {
					filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
				}
				return &view.Expr{Value: filter}, nil
			}
		} else {
			filter := ""
			if strings.ToLower(op) == "regex" {
				filter = fmt.Sprintf("match(%s,%s)", t.Tag, t.Value)
			} else {
				filter = fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
			}
			return &view.Expr{Value: filter}, nil
		}
	}
	whereFilter := tagItem.WhereTranslator
	if whereFilter != "" {
		switch t.Tag {
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
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value, valueInt, valueInt)
		case "tap_port":
			valueStr := strings.Trim(t.Value, "'")
			mac, err := net.ParseMAC(valueStr)
			if err != nil {
				return nil, err
			}
			valueUInt64 := utils.Mac2Uint64(mac)
			whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, valueUInt64)
		default:
			switch strings.ToLower(op) {
			case "regexp":
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "match", t.Value)
			case "not regexp":
				whereFilter = fmt.Sprintf(tagItem.WhereRegexpTranslator, "NOT match", t.Value)
			default:
				whereFilter = fmt.Sprintf(tagItem.WhereTranslator, op, t.Value)
			}
		}
	} else {
		filter := fmt.Sprintf("%s %s %s", t.Tag, op, t.Value)
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
