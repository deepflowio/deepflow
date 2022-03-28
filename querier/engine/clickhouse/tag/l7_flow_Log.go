package tag

var L7TagMap = GenerateL7TagMap()

func GetL7Tag(name string) (*Tag, bool) {
	tag, ok := L7TagMap[name]
	return tag, ok
}

func GenerateL7TagMap() map[string]*Tag {
	l7TagMap := make(map[string]*Tag)

	// response_code
	l7TagMap["response_code"] = NewTag(
		"",
		"isNotNull(response_code)",
		"",
	)
	return l7TagMap
}
