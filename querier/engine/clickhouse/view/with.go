package view

import (
	"bytes"
)

// NodeSet With结构体集合
type Withs struct {
	Withs []Node
}

func (s *Withs) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Withs) getList() []Node {
	return s.Withs
}

func (s *Withs) WriteTo(buf *bytes.Buffer) {
	for i, tag := range s.Withs {
		tag.WriteTo(buf)
		if i < len(s.Withs)-1 {
			buf.WriteString(", ")
		}
	}
}

func (s *Withs) Append(w *With) {
	s.Withs = append(s.Withs, w)
}

func (s *Withs) IsNull() bool {
	if len(s.Withs) < 1 {
		return true
	} else {
		return false
	}
}

func (s *Withs) GetWiths() []Node {
	return s.Withs
}

type With struct {
	Value string
	Alias string
	NodeBase
}

func (n *With) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
	if n.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(n.Alias)
	}
}

func (n *With) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}
