package jsonparser

import (
	"github.com/bitly/go-simplejson"
)

// GetTheMaxSizeOfAttr 获取 Json 数组中 attr 属性的最大长度，用于确定格式化输出时列的宽度
func GetTheMaxSizeOfAttr(data *simplejson.Json, attr string) int {
	var size int
	if _, err := data.Array(); err != nil {
		return 0
	}
	for i := range data.MustArray() {
		row := data.GetIndex(i)
		length := len(row.Get(attr).MustString())
		if length > size {
			size = length
		}
	}
	if size < len(attr) {
		size = len(attr)
	}
	return size
}
