package tag

import (
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("tag")

type Tag struct {
	TagGenerator     []string // select的字段如何生成
	TagGeneratorName []string // 生成的tag名称
	TagTranslator    string   // 对生成的tag进行翻译或转换
	NotNullFilter    string
	WhereTranslator  string
}

func NewTag(tagGenerator, tagGeneraterName []string, tagTranslator, notNullFilter, whereTranslator string) *Tag {
	return &Tag{
		TagGenerator:     tagGenerator,
		TagGeneratorName: tagGeneraterName,
		TagTranslator:    tagTranslator,
		NotNullFilter:    notNullFilter,
		WhereTranslator:  whereTranslator,
	}
}
