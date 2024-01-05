/*
 * Copyright (c) 2024 Yunshan Networks
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
		alias := strings.Trim(n.Alias, "`")
		buf.WriteString("`")
		buf.WriteString(alias)
		buf.WriteString("`")
	}
}

func (n *With) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}
