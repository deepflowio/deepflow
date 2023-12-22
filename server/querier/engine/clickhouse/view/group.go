/*
 * Copyright (c) 2023 Yunshan Networks
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
	Alias string
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
	if n.Alias != "" {
		buf.WriteString(n.Value)
		buf.WriteString(" AS ")
		buf.WriteString("`")
		buf.WriteString(strings.Trim(n.Alias, "`"))
		buf.WriteString("`")
	} else if strings.Contains(n.Value, ",") {
		buf.WriteString(n.Value)
	} else {
		buf.WriteString("`")
		buf.WriteString(strings.Trim(n.Value, "`"))
		buf.WriteString("`")
	}
}

func (n *Group) GetWiths() []Node {
	return n.Withs
}
