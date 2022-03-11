package view

import (
	"bytes"
)

// NodeSet Group结构体集合
type Groups struct {
	groups []Node
	NodeSetBase
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

func (s *Groups) GetWiths() []Node {
	var withs []Node
	for _, node := range s.groups {
		if nodeWiths := node.GetWiths(); nodeWiths != nil {
			withs = append(withs, nodeWiths...)
		}
	}
	return withs
}

type Group struct {
	Value string
	Flag  int
	Withs []Node
	NodeBase
}

func (n *Group) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Group) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
}

func (n *Group) GetWiths() []Node {
	return n.Withs
}
