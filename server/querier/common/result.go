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

package common

import (
	"strings"
)

const (
	COLUMN_SCHEMA_TYPE_TAG = iota
	COLUMN_SCHEMA_TYPE_METRICS
)

type Result struct {
	Columns []interface{}
	Values  []interface{}
	Schemas ColumnSchemas
}

func (r *Result) ToJson() map[string]interface{} {
	return map[string]interface{}{
		"columns": r.Columns,
		"values":  r.Values,
		"schemas": r.Schemas.ToArray(),
	}
}

type ColumnSchema struct {
	Name      string
	Unit      string
	Type      int
	ValueType string
	PreAS     string
	LabelType string
}

func (c *ColumnSchema) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"unit":       c.Unit,
		"type":       c.Type,
		"value_type": c.ValueType,
		"pre_as":     c.PreAS,
		"label_type": c.LabelType,
	}
}

func NewColumnSchema(name, preAS, labelType string) *ColumnSchema {
	return &ColumnSchema{Name: strings.Trim(name, "`"), PreAS: preAS, LabelType: labelType}
}

type ColumnSchemas []*ColumnSchema

func (c *ColumnSchemas) ToArray() []interface{} {
	schemas := []interface{}{}
	for _, schema := range *c {
		schemas = append(schemas, schema.ToMap())
	}
	return schemas
}
