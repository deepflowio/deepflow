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
	IsField bool
}

func (n *Order) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Order) WriteTo(buf *bytes.Buffer) {
	if n.IsField {
		buf.WriteString("`")
		buf.WriteString(strings.Trim(n.SortBy, "`"))
		buf.WriteString("`")
	} else {
		buf.WriteString(n.SortBy)
	}
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
