package tag

import (
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("tag")

type Tag struct {
	TagTranslator   string // 对tag进行翻译或转换
	NotNullFilter   string
	WhereTranslator string
}

func NewTag(tagTranslator, notNullFilter, whereTranslator string) *Tag {
	return &Tag{
		TagTranslator:   tagTranslator,
		NotNullFilter:   notNullFilter,
		WhereTranslator: whereTranslator,
	}
}
