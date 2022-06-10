package qingcloud

type Param struct {
	Name  string
	Value interface{}
}

// Params 请求参数数组
type Params []*Param

// Len 长度
func (ps Params) Len() int {
	return len(ps)
}

// Swap swap
func (ps Params) Swap(i, j int) { ps[i], ps[j] = ps[j], ps[i] }

// Less less
func (ps Params) Less(i, j int) bool { return ps[i].Name < ps[j].Name }
