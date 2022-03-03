package view

import (
	"bytes"
)

// NodeSet Tag结构体集合
type Tags struct {
	tags []Node
}

func (s *Tags) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Tags) getList() []Node {
	return s.tags
}

func (s *Tags) isNull() bool {
	if len(s.tags) < 1 {
		return true
	} else {
		return false
	}
}

func (s *Tags) Append(t *Tag) {
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

type Tag struct {
	Value string
	Alias string
	Flag  int
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
