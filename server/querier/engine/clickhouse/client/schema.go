package client

const (
	COLUMN_SCHEMA_TYPE_TAG = iota
	COLUMN_SCHEMA_TYPE_METRICS
)

type ColumnSchema struct {
	Name string
	Unit string
	Type int
}

func (c *ColumnSchema) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"unit": c.Unit,
		"type": c.Type,
	}
}

func NewColumnSchema(name string) *ColumnSchema {
	return &ColumnSchema{Name: name}
}
