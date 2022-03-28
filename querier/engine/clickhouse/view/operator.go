package view

import (
	"bytes"
	"strings"
)

const (
	OPERATOER_UNKNOWN int = iota
	AND
	OR
	NOT
	GTE
	LTE
)

type Operator struct {
	Type int
	NodeBase
}

func (n *Operator) ToString() string {
	switch n.Type {
	case AND:
		return " AND "
	case OR:
		return " OR "
	case NOT:
		return "NOT "
	case GTE:
		return " >= "
	case LTE:
		return " <= "
	}
	return ""
}

func (n *Operator) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.ToString())
}

func GetOperator(op string) (*Operator, int) {
	op = strings.TrimSpace(op)
	op = strings.ToLower(op)
	var opType int
	switch op {
	case ">=":
		opType = GTE
	case "<=":
		opType = LTE
	case "not":
		opType = NOT
	case "and":
		opType = AND
	case "or":
		opType = OR
	}
	return &Operator{Type: opType}, opType
}
