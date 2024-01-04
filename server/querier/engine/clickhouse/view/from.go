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
)

// NodeSet Table结构体集合
type Tables struct {
	tables []Node
	NodeSetBase
}

func (t *Tables) getList() []Node {
	return t.tables
}

func (t *Tables) ToString() string {
	buf := bytes.Buffer{}
	t.WriteTo(&buf)
	return buf.String()
}

func (t *Tables) WriteTo(buf *bytes.Buffer) {
	for i, table := range t.tables {
		switch table.(type) {
		case *Table:
			table.WriteTo(buf)
		default:
			buf.WriteString("(")
			table.WriteTo(buf)
			buf.WriteString(")")
		}
		if i < len(t.tables)-1 {
			buf.WriteString(", ")
		}
	}
}

func (t *Tables) IsNull() bool {
	if len(t.tables) < 1 {
		return true
	} else {
		return false
	}
}

func (t *Tables) Append(g Node) {
	t.tables = append(t.tables, g)
}

type Table struct {
	NodeBase
	Value string
}

func (t *Table) ToString() string {
	return t.Value
}

func (t *Table) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(t.Value)
}
