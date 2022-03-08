package view

import (
	"bytes"
)

type Filters struct {
	Expr  Node
	Withs []*With
}

func (s *Filters) IsNull() bool {
	if s.Expr == nil {
		return true
	} else {
		return false
	}
}

func (s *Filters) Append(f *Filters) {
	if f.IsNull() {
		return
	}
	if s.Expr == nil {
		s.Expr = f.Expr
	} else {
		s.Expr = &BinaryExpr{Left: s.Expr, Right: f.Expr, Op: Operator{Type: AND}}
		if len(f.Withs) > 0 {
			s.Withs = append(s.Withs, f.Withs...)
		}
	}
}

func (s *Filters) WriteTo(buf *bytes.Buffer) {
	s.Expr.WriteTo(buf)
}

func (n *Filters) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

// 括号
type Nested struct {
	Expr Node
}

func (n *Nested) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Nested) WriteTo(buf *bytes.Buffer) {
	buf.WriteString("(")
	n.Expr.WriteTo(buf)
	buf.WriteString(")")
}

// AND OR NOT
type BinaryExpr struct {
	Left  Node
	Right Node
	Op    Operator
}

func (n *BinaryExpr) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *BinaryExpr) WriteTo(buf *bytes.Buffer) {
	n.Left.WriteTo(buf)
	n.Op.WriteTo(buf)
	n.Right.WriteTo(buf)
}

type UnaryExpr struct {
	Op   Operator
	Expr Node
}

func (n *UnaryExpr) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *UnaryExpr) WriteTo(buf *bytes.Buffer) {
	n.Op.WriteTo(buf)
	n.Expr.WriteTo(buf)
}

type Expr struct {
	Value string
}

func (n *Expr) ToString() string {
	return n.Value
}

func (n *Expr) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
}
