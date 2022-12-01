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
}

func (c *ColumnSchema) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"unit":       c.Unit,
		"type":       c.Type,
		"value_type": c.ValueType,
	}
}

func NewColumnSchema(name string) *ColumnSchema {
	return &ColumnSchema{Name: strings.Trim(name, "`")}
}

type ColumnSchemas []*ColumnSchema

func (c *ColumnSchemas) ToArray() []interface{} {
	schemas := []interface{}{}
	for _, schema := range *c {
		schemas = append(schemas, schema.ToMap())
	}
	return schemas
}
