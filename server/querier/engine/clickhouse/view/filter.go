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

type Filters struct {
	Expr  Node
	Withs []Node
	NodeSetBase
}

func (s *Filters) IsNull() bool {
	if s.Expr == nil {
		return true
	} else {
		return false
	}
}

func (s *Filters) GetWiths() []Node {
	return s.Withs
}

func (s *Filters) Append(f *Filters) {
	if f.IsNull() {
		return
	}
	if s.Expr == nil {
		s.Expr = f.Expr
		s.Withs = f.Withs
	} else {
		s.Expr = &BinaryExpr{Left: s.Expr, Right: f.Expr, Op: &Operator{Type: AND}}
		if len(f.Withs) > 0 {
			s.Withs = append(s.Withs, f.Withs...)
		}
	}
}

func (s *Filters) ToString() string {
	buf := bytes.Buffer{}
	s.WriteTo(&buf)
	return buf.String()
}

func (s *Filters) WriteTo(buf *bytes.Buffer) {
	s.Expr.WriteTo(buf)
}

// 括号
type Nested struct {
	NodeBase
	Expr Node
}

func (n *Nested) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Nested) WriteTo(buf *bytes.Buffer) {
	buf.WriteString("(")
	n.Expr.WriteTo(buf)
	buf.WriteString(")")
}

type BinaryExpr struct {
	NodeBase
	Left  Node
	Right Node
	Op    *Operator
}

func (n *BinaryExpr) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *BinaryExpr) WriteTo(buf *bytes.Buffer) {
	n.Left.WriteTo(buf)
	n.Op.WriteTo(buf)
	n.Right.WriteTo(buf)
}

type UnaryExpr struct {
	NodeBase
	Op   *Operator
	Expr Node
}

func (n *UnaryExpr) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *UnaryExpr) WriteTo(buf *bytes.Buffer) {
	n.Op.WriteTo(buf)
	n.Expr.WriteTo(buf)
}

type Expr struct {
	NodeBase
	Value string
}

func (n *Expr) ToString() string {
	buf := bytes.Buffer{}
	n.WriteTo(&buf)
	return buf.String()
}

func (n *Expr) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.Value)
}
