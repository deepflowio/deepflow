package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
	"metaflow/querier/parse"
)

type CHEngine struct {
	Model      *view.Model
	statements []Statement
	IP         string
}

// 翻译单元,翻译结果写入view.Model
type Statement interface {
	Format(*view.Model)
}

func (e *CHEngine) Init() {
	e.Model = view.NewModel()
}

func (e *CHEngine) AddTag(tag string, alias string) {
	var stmt Statement
	// 根据tag字段返回具体tag单元结构体
	switch tag {
	// TODO: tag常量结构替换&Flag常量结构替换
	case "host":
		stmt = &TagHost{Alias: alias}
	default:
		stmt = &TagDefault{Value: tag, Alias: alias}
	}
	e.statements = append(e.statements, stmt)
}

func (e *CHEngine) AddGroup(group string) {
	var stmt Statement
	// 根据group字段返回具体group单元结构体
	switch group {
	// TODO: group常量结构替换&Flag常量结构替换
	case "host":
		stmt = &GroupHost{}
	default:
		stmt = &GroupDefault{Value: group}
	}
	e.statements = append(e.statements, stmt)
}

func (e *CHEngine) AddTable(table string) {
	stmt := &Table{Value: table}
	e.statements = append(e.statements, stmt)
}

// 原始sql转为clickhouse-sql
func (e *CHEngine) ToSQLString() string {
	for _, stmt := range e.statements {
		stmt.Format(e.Model)
	}
	// 使用Model生成View
	chView := view.NewView(e.Model)
	// View生成clickhouse-sql
	chSql := chView.ToString()
	return chSql
}

func (e *CHEngine) ExecuteQuery(sql string) ([]string, error) {
	parser := parse.Parser{Engine: e}
	parser.ParseSQL(sql)
	//chSql := e.ToSQLString()
	return nil, nil
}
