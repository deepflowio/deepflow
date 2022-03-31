package tag

var L4TagMap = GenerateL4TagMap()

func GetL4Tag(name string) (map[string]*Tag, bool) {
	tag, ok := L4TagMap[name]
	return tag, ok
}

func GenerateL4TagMap() map[string]map[string]*Tag {
	l4TagMap := make(map[string]map[string]*Tag)

	// 响应码
	l4TagMap["response_code"] = map[string]*Tag{
		"default": NewTag(
			"",
			"isNotNull(response_code)",
			"",
			"",
		)}
	// 采集点ID
	l4TagMap["tap_type_value_id"] = map[string]*Tag{
		"default": NewTag(
			"tap_type",
			"",
			"tap_type %s %s",
			"",
		)}
	// 采集点
	l4TagMap["tap_type_value"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.tap_type_map, ('name'), toUInt64(tap_type))",
			"",
			"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE name %s %s)",
			"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE %s(name,%s))",
		)}
	// IP类型
	l4TagMap["ip_version"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, 4, 6)",
			"",
			"is_ipv4 %s %s",
			"",
		)}
	// _ID
	l4TagMap["_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"_id %s %s AND time=toDateTime(bitShiftRight(%v, 32)) AND toStartOfHour(time)=toStartOfHour(toDateTime(bitShiftRight(%v, 32)))",
			"",
		)}
	// 采集位置名称
	l4TagMap["tap_port_name"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.vtap_port_map, ('name'), (toUInt64(vtap_id),toUInt64(tap_port)))",
			"",
			// TODO whereTranslator
			"",
			"",
		)}
	// 采集器名称
	l4TagMap["vtap"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.vtap_map, ('name'), toUInt64(vtap_id))",
			"",
			"",
			"",
		)}
	return l4TagMap
}
