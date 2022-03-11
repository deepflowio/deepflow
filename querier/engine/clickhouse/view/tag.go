package view

import (
	"bytes"
)

// NodeSet Tag结构体集合
type Tags struct {
	tags []Node
	NodeSetBase
}

func (s *Tags) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Tags) getList() []Node {
	return s.tags
}

func (s *Tags) IsNull() bool {
	if len(s.tags) < 1 {
		return true
	} else {
		return false
	}
}

func (s *Tags) Append(t Node) {
	s.tags = append(s.tags, t)
}

func (s *Tags) WriteTo(buf *bytes.Buffer) {
	for i, tag := range s.tags {
		tag.WriteTo(buf)
		if i < len(s.tags)-1 {
			buf.WriteString(", ")
		}
	}
}

func (s *Tags) GetWiths() []Node {
	var withs []Node
	for _, node := range s.tags {
		if nodeWiths := node.GetWiths(); nodeWiths != nil {
			withs = append(withs, nodeWiths...)
		}
	}
	return withs
}

type Tag struct {
	Value string
	Alias string
	Flag  int
	Withs []Node
	NodeBase
}

func (n *Tag) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Tag) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
	if n.Alias != "" {
		buf.WriteString(" AS ")
		buf.WriteString(n.Alias)
	}
}

func (n *Tag) GetWiths() []Node {
	return n.Withs
}
