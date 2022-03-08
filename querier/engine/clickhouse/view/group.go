package view

import (
	"bytes"
)

// NodeSet Group结构体集合
type Groups struct {
	groups []Node
}

func (s *Groups) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Groups) getList() []Node {
	return s.groups
}

func (s *Groups) WriteTo(buf *bytes.Buffer) {
	for i, tag := range s.groups {
		tag.WriteTo(buf)
		if i < len(s.groups)-1 {
			buf.WriteString(", ")
		}
	}
}

func (s *Groups) IsNull() bool {
	if len(s.groups) < 1 {
		return true
	} else {
		return false
	}
}

func (s *Groups) Append(g *Group) {
	s.groups = append(s.groups, g)
}

type Group struct {
	Value string
	Flag  int
}

func (n *Group) ToString() string {
	return n.Value
}

func (n *Group) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
}
