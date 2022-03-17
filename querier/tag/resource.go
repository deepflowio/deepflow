package tag

import (
	"errors"
	"fmt"
)

func GetTag(name string) (*Tag, error) {
	tag, ok := TagMap[name]
	if !ok {
		errMessage := fmt.Sprintf("get tag %s failed", name)
		err := errors.New(errMessage)
		log.Error(err)
		return &Tag{}, err
	}
	return tag, nil
}

var TagMap = map[string]*Tag{
	"region": NewTag(
		"region",
		[]string{""},
		[]string{"region_id"},
		"region_id",
		"region_id!=0",
		"region_id %s %s", // 第一个参数是操作符，第二个参数是过滤的值
	),
	"region_name": NewTag(
		"region_name",
		[]string{""},
		[]string{"region_id"},
		"dictGet(deepflow.region_map, ('name'), (toUInt64(region_id)))",
		"region_id!=0",
		"region_id IN (SELECT toUInt16(id) FROM deepflow.region_map WHERE name %s %s)",
	),
	"region_0": NewTag(
		"region_0",
		[]string{""},
		[]string{"region_id_0"},
		"region_id_0",
		"region_id_0!=0",
		"region_id_0 %s %s", // 第一个参数是操作符，第二个参数是过滤的值
	),
	"region_name_0": NewTag(
		"region_name_0",
		[]string{""},
		[]string{"region_id_0"},
		"dictGet(deepflow.region_map, ('name'), (toUInt64(region_id_0)))",
		"region_id_0!=0",
		"region_id_0 IN (SELECT toUInt16(id) FROM deepflow.region_map WHERE name %s %s)",
	),
}
