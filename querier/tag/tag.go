package tag

import (
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("tag")

type Tag struct {
	Name             string   // 对外提供的tag字段
	TagGenerator     []string // select的字段如何生成
	TagGeneratorName []string // 生成的tag名称
	TagTranslator    string   // 对生成的tag进行翻译或转换
	NotNullFilter    string
	WhereTranslator  string
}

func NewTag(name string, tagGenerater, tagGeneraterName []string, tagTranslator, notNullFilter, whereTranslator string) *Tag {
	return &Tag{
		Name:             name,
		TagGenerator:     tagGenerater,
		TagGeneratorName: tagGeneraterName,
		TagTranslator:    tagTranslator,
		NotNullFilter:    notNullFilter,
		WhereTranslator:  whereTranslator,
	}
}
