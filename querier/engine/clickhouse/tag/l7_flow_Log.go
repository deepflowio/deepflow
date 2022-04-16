package tag

var L7TagMap = GenerateL7TagMap()

func GetL7Tag(name string) (map[string]*Tag, bool) {
	tag, ok := L7TagMap[name]
	return tag, ok
}

func GenerateL7TagMap() map[string]map[string]*Tag {
	l7TagMap := make(map[string]map[string]*Tag)

	// 响应码
	l7TagMap["response_code"] = map[string]*Tag{
		"default": NewTag(
			"",
			"isNotNull(response_code)",
			"",
			"",
		)}
	// 采集点ID
	l7TagMap["tap_id"] = map[string]*Tag{
		"default": NewTag(
			"tap_type",
			"",
			"tap_type %s %s",
			"",
		)}
	// 采集点
	l7TagMap["tap"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.tap_type_map, 'name', toUInt64(tap_type))",
			"",
			"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE name %s %s)",
			"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE %s(name,%s))",
		)}
	// IP类型
	l7TagMap["ip_version"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, 4, 6)",
			"",
			"is_ipv4 %s %s",
			"",
		)}
	// ID
	l7TagMap["_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"_id %s %s AND time=toDateTime(bitShiftRight(%v, 32)) AND toStartOfHour(time)=toStartOfHour(toDateTime(bitShiftRight(%v, 32)))",
			"",
		)}
	// 采集位置标识
	l7TagMap["tap_port"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"tap_port %s %v",
			"",
		)}
	// 采集位置名称
	l7TagMap["tap_port_name"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.vtap_port_map, 'name', (toUInt64(vtap_id),toUInt64(tap_port)))",
			"",
			"toUInt64(tap_port) IN (SELECT tap_port FROM deepflow.vtap_port_map WHERE name %s %s)",
			"toUInt64(tap_port) IN (SELECT tap_port FROM deepflow.vtap_port_map WHERE %s(name,%s))",
		)}
	return l7TagMap
}
