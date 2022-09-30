package jsonparser

import (
	"github.com/bitly/go-simplejson"
)

// GetTheMaxSizeOfAttr 获取 Json 数组中 attr 属性的最大长度，用于确定格式化输出时列的宽度
func GetTheMaxSizeOfAttr(data *simplejson.Json, attr string) (int, error) {
	array, err := data.Array()
	if err != nil {
		return 0, err
	}
	var size int
	for i := range array {
		row := data.GetIndex(i)
		length := len(row.Get(attr).MustString())
		if length > size {
			size = length
		}
	}
	return size, nil
}
