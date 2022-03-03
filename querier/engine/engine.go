package engine

type Engine interface {
	AddTag(string, string)
	AddTable(string)
	AddGroup(string)
	ToSQLString() string
	Init()
	ExecuteQuery(string) ([]string, error)
}
