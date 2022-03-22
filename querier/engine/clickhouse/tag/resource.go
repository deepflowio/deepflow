package tag

import (
	"errors"
	"fmt"
)

var TagResoureMap = GenerateTagResoureMap()

func GetTag(name string) (*Tag, error) {
	tag, ok := TagResoureMap[name]
	if !ok {
		errMessage := fmt.Sprintf("get tag %s failed", name)
		err := errors.New(errMessage)
		log.Error(err)
		return &Tag{}, err
	}
	return tag, nil
}

func GenerateTagResoureMap() map[string]*Tag {
	tagResourceMap := make(map[string]*Tag)
	for _, resourceStr := range []string{"region", "az", "pod_node", "pod_ns", "pod_group", "pod", "pod_cluster", "subnet"} {
		// 资源ID
		tagResourceMap[resourceStr] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id"},
			resourceStr+"_id",
			resourceStr+"_id != 0",
			resourceStr+"_id %s %s", // 第一个参数是操作符，第二个参数是过滤的值
		)
		// 资源名称
		tagResourceMap[resourceStr+"_name"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id)))",
			resourceStr+"_id != 0",
			resourceStr+"_id IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
		// 客户端资源ID
		tagResourceMap[resourceStr+"_0"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_0"},
			resourceStr+"_id_0",
			resourceStr+"_id_0 != 0",
			resourceStr+"_id_0 %s %s",
		)
		// 客户端资源名称
		tagResourceMap[resourceStr+"_name_0"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_0"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_0)))",
			resourceStr+"_id_0 != 0",
			resourceStr+"_id_0 IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
		// 服务端资源ID
		tagResourceMap[resourceStr+"_1"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_1"},
			resourceStr+"_id_1",
			resourceStr+"_id_1 != 0",
			resourceStr+"_id_1 %s %s",
		)
		// 服务端资源名称
		tagResourceMap[resourceStr+"_name_1"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_1"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_1)))",
			resourceStr+"_id_1 != 0",
			resourceStr+"_id_1 IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
	}
	return tagResourceMap
}
