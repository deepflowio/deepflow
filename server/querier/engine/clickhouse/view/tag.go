/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package view

import (
	"bytes"
	"strings"
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
		buf.WriteString("`")
		buf.WriteString(strings.Trim(n.Alias, "`"))
		buf.WriteString("`")
	}
}

func (n *Tag) GetWiths() []Node {
	return n.Withs
}
