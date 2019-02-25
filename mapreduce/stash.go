package mapreduce

type Stash interface {
	Add(docs []interface{}) ([]interface{}, uint64)
	Size() int
	Dump() []interface{}
	Clear()
	GetWindowRight() uint32
	SetTimestamp(ts uint32)
}
