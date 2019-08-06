package mapreduce

type Stash interface {
	Add(docs []interface{}) []interface{}
	Size() int
	Dump() []interface{}
	Clear()
	GetWindowRight() uint32
	SetTimestamp(ts uint32)
}
