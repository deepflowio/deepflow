package tag

type Tag struct {
	TagTranslator         string // 对tag进行翻译或转换
	NotNullFilter         string // 资源非空过滤
	WhereTranslator       string // 资源过滤转换
	WhereRegexpTranslator string // 资源过滤正则转换
}

func NewTag(tagTranslator, notNullFilter, whereTranslator, whereRegexpTranslator string) *Tag {
	return &Tag{
		TagTranslator:         tagTranslator,
		NotNullFilter:         notNullFilter,
		WhereTranslator:       whereTranslator,
		WhereRegexpTranslator: whereRegexpTranslator,
	}
}

var TABLE_TAG_MAP = map[string]map[string]map[string]*Tag{
	"flow_log-l4_flow_log": L4TagMap,
	"flow_log-l7_flow_log": L7TagMap,
}

func GetTag(name, db, table, function string) (*Tag, bool) {
	tag, ok := TagResoureMap[name][function]
	if !ok {
		tagMap, ok := TABLE_TAG_MAP[db+"-"+table]
		if ok {
			tag, ok := tagMap[name][function]
			return tag, ok
		}
	}
	return tag, ok
}
