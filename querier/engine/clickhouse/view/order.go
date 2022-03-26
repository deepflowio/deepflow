package view

import (
	"bytes"
)

type Orders struct {
	NodeSetBase
	Orders []Node
}

func (s *Orders) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Orders) getList() []Node {
	return s.Orders
}

func (s *Orders) Append(o Node) {
	s.Orders = append(s.Orders, o)
}

func (s *Orders) WriteTo(buf *bytes.Buffer) {
	for i, order := range s.Orders {
		order.WriteTo(buf)
		if i < len(s.Orders)-1 {
			buf.WriteString(",")
		}
	}
}

func (s *Orders) IsNull() bool {
	if len(s.Orders) < 1 {
		return true
	} else {
		return false
	}
}

type Order struct {
	NodeBase
	SortBy  string
	OrderBy string
}

func (n *Order) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Order) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.SortBy)
	buf.WriteString(" ")
	if n.OrderBy == "" {
		buf.WriteString("ASC")
	} else {
		buf.WriteString(n.OrderBy)
	}
}

type Limit struct {
	NodeBase
	Limit  string
	Offset string
}

func (n *Limit) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Limit) WriteTo(buf *bytes.Buffer) {
	if n.Limit != "" {
		buf.WriteString(" LIMIT ")
		if n.Offset != "" {
			buf.WriteString(n.Offset)
			buf.WriteString(", ")
		}
		buf.WriteString(n.Limit)

	}
}
