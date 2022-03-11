package view

import (
	"bytes"
)

const (
	AND int = iota
	OR
	NOT
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
	}
	return ""
}

func (n *Operator) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.ToString())
}
