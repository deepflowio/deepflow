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

const (
	OPERATOER_UNKNOWN int = iota
	AND
	OR
	NOT
	GTE
	LTE
	EQ
	NEQ
	LIKE
	NLIKE
	REGEXP
	NREGEXP
	GT
	LT
	IN
	NIN
)

type Operator struct {
	Type int
	NodeBase
}

func (n *Operator) ToString() string {
	switch n.Type {
	case AND:
		return " AND "
	case OR:
		return " OR "
	case NOT:
		return "NOT "
	case GTE:
		return " >= "
	case LTE:
		return " <= "
	case EQ:
		return " = "
	case NEQ:
		return " != "
	case LIKE:
		return " LIKE "
	case NLIKE:
		return " NOT LIKE "
	case REGEXP:
		return " MATCH "
	case NREGEXP:
		return " NOT MATCH "
	case GT:
		return " > "
	case LT:
		return " < "
	case IN:
		return " IN "
	case NIN:
		return " NOT IN "
	}
	return ""
}

func (n *Operator) WriteTo(buf *bytes.Buffer) {
	buf.WriteString(n.ToString())
}

func GetOperator(op string) (*Operator, int) {
	op = strings.TrimSpace(op)
	op = strings.ToLower(op)
	var opType int
	switch op {
	case ">=":
		opType = GTE
	case "<=":
		opType = LTE
	case "not":
		opType = NOT
	case "and":
		opType = AND
	case "or":
		opType = OR
	case "=":
		opType = EQ
	case "!=":
		opType = NEQ
	case "like":
		opType = LIKE
	case "not like":
		opType = NLIKE
	case "regexp":
		opType = REGEXP
	case "not regexp":
		opType = NREGEXP
	case ">":
		opType = GT
	case "<":
		opType = LT
	case "in":
		opType = IN
	case "not in":
		opType = NIN
	}
	return &Operator{Type: opType}, opType
}
