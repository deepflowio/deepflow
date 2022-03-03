package view

import (
	"bytes"
)

// NodeSet With结构体集合
type Withs struct {
	withs []Node
}

func (s *Withs) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Withs) getList() []Node {
	return s.withs
}

func (s *Withs) WriteTo(buf *bytes.Buffer) {
	for i, tag := range s.withs {
		tag.WriteTo(buf)
		if i < len(s.withs)-1 {
			buf.WriteString(", ")
		}
	}
}

func (s *Withs) Append(w *With) {
	s.withs = append(s.withs, w)
}

func (s *Withs) isNull() bool {
	if len(s.withs) < 1 {
		return true
	} else {
		return false
	}
}

type With struct {
	Value string
	Alias string
	Flag  int
}

func (n *With) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *With) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
	if n.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(n.Alias)
	}
}
