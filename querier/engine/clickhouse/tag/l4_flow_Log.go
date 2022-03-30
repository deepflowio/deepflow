package tag

var L4TagMap = GenerateL4TagMap()

func GetL4Tag(name string) (*Tag, bool) {
	tag, ok := L4TagMap[name]
	return tag, ok
}

func GenerateL4TagMap() map[string]*Tag {
	l4TagMap := make(map[string]*Tag)

	// 响应码
	l4TagMap["response_code"] = NewTag(
		"",
		"isNotNull(response_code)",
		"",
		"",
	)
	// 采集点ID
	l4TagMap["tap_type_value_id"] = NewTag(
		"tap_type",
		"",
		"tap_type %s %s",
		"",
	)
	// 采集点
	l4TagMap["tap_type_value"] = NewTag(
		"dictGet(deepflow.tap_type_map, ('name'), toUInt64(tap_type))",
		"",
		"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE name %s %s)",
		"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE %s(name,%s))",
	)
	// IP类型
	l4TagMap["ip_version"] = NewTag(
		"if(is_ipv4=1, 4, 6)",
		"",
		"is_ipv4 %s %s",
		"",
	)
	// 是否匹配服务
	l4TagMap["include_service"] = NewTag(
		"",
		"",
		"is_key_service %s %s",
		"",
	)
	// ID
	l4TagMap["_id"] = NewTag(
		"",
		"",
		"_id %s %s AND time=bitShiftRight(%s, 32) AND toStartOfHour(time)=toStartOfHourbitShiftRight(%s, 32)",
		"",
	)
	return l4TagMap
}
