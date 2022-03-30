package tag

import (
	"strconv"

	"metaflow/querier/common"
)

var TagResoureMap = GenerateTagResoureMap()

func GetTag(name string) (*Tag, bool) {
	tag, ok := TagResoureMap[name]
	return tag, ok
}

var DeviceMap = map[string]int{
	"vm":          common.VIF_DEVICE_TYPE_VM,
	"router":      common.VIF_DEVICE_TYPE_VROUTER,
	"dhcp_port":   common.VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": common.VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         common.VIF_DEVICE_TYPE_RDS_INSTANCE,
	"lb":          common.VIF_DEVICE_TYPE_LB,
	"nat_gateway": common.VIF_DEVICE_TYPE_NAT_GATEWAY,
}

func GenerateTagResoureMap() map[string]*Tag {
	tagResourceMap := make(map[string]*Tag)
	for _, resourceStr := range []string{"region", "az", "pod_node", "pod_ns", "pod_group", "pod", "pod_cluster", "subnet", "l3_epc"} {
		// 资源ID
		notExistID := "0"
		if resourceStr == "l3_epc" {
			notExistID = "-2"
		}
		tagResourceMap[resourceStr+"_id"] = NewTag(
			"",
			resourceStr+"_id !="+notExistID,
			"",
		)
		// 资源名称
		tagResourceMap[resourceStr] = NewTag(
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id)))",
			resourceStr+"_id != "+notExistID,
			"toUInt64("+resourceStr+"_id) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
		)
		// 客户端资源ID
		tagResourceMap[resourceStr+"_id_0"] = NewTag(
			"",
			resourceStr+"_id_0 != "+notExistID,
			"",
		)
		// 客户端资源名称
		tagResourceMap[resourceStr+"_0"] = NewTag(
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_0)))",
			resourceStr+"_id_0 != "+notExistID,
			"toUInt64("+resourceStr+"_id_0) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
		)
		// 服务端资源ID
		tagResourceMap[resourceStr+"_id_1"] = NewTag(
			"",
			resourceStr+"_id_1 != "+notExistID,
			"",
		)
		// 服务端资源名称
		tagResourceMap[resourceStr+"_1"] = NewTag(
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_1)))",
			resourceStr+"_id_1 != "+notExistID,
			"toUInt64("+resourceStr+"_id_1) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
		)
	}
	for resourceStr, deviceType := range DeviceMap {
		deviceTypeStr := strconv.Itoa(deviceType)
		// device资源ID
		tagResourceMap[resourceStr+"_id"] = NewTag(
			"if(l3_device_type="+deviceTypeStr+",l3_device_id, 0)",
			"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
			"l3_device_id %s %s",
		)
		// device资源名称
		tagResourceMap[resourceStr] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id)))",
			"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
			"toUInt64(l3_device_id) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
		// 客户端device资源ID
		tagResourceMap[resourceStr+"_id_0"] = NewTag(
			"if(l3_device_type_0="+deviceTypeStr+",l3_device_id_0, 0)",
			"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
			"l3_device_id_0 %s %s",
		)
		// 客户端device资源名称
		tagResourceMap[resourceStr+"_0"] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_0)))",
			"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
			"toUInt64(l3_device_id_0) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
		// 服务端device资源ID
		tagResourceMap[resourceStr+"_id_1"] = NewTag(
			"if(l3_device_type_1="+deviceTypeStr+",l3_device_id_1, 0)",
			"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
			"l3_device_id_1 %s %s",
		)
		// 服务端device资源名称
		tagResourceMap[resourceStr] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_1)))",
			"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
			"toUInt64(l3_device_id_1) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
	}

	for _, autoStr := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
		autoID := autoStr + "_id"
		autoType := autoStr + "_type"
		// 自动分组资源名称
		tagResourceMap[autoStr] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"),toUInt64("+autoID+")))",
			"",
			"toUInt64("+autoID+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
		// 自动分组客户端资源名称
		tagResourceMap[autoStr+"_0"] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"_0),toUInt64("+autoID+"_0)))",
			"",
			"toUInt64("+autoID+"_0) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
		// 自动分组服务端资源名称
		tagResourceMap[autoStr+"_1"] = NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"_1),toUInt64("+autoID+"_1)))",
			"",
			"toUInt64("+autoID+"_1) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
		)
	}

	// 采集点ID
	tagResourceMap["tap_type_id"] = NewTag(
		"tap_type",
		"",
		"tap_type %s %s",
	)
	// 采集点
	tagResourceMap["tap_type"] = NewTag(
		"dictGet(deepflow.tap_type_map, ('name'), toUInt64(tap_type))",
		"",
		"toUInt64(tap_type) IN (SELECT value FROM deepflow.tap_type_map WHERE name %s %s)",
	)

	// IP
	tagResourceMap["ip"] = NewTag(
		"if(is_ipv4=1, IPv4NumToString(ip4), IPv6NumToString(ip6))",
		"",
		"is_ipv4=%s AND (ip%s %s %s)",
	)
	// 客户端IP
	tagResourceMap["ip_0"] = NewTag(
		"if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))",
		"",
		"is_ipv4=%s AND (ip%s_0 %s %s)",
	)
	// 服务端IP
	tagResourceMap["ip_1"] = NewTag(
		"if(is_ipv4=1, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1))",
		"",
		"is_ipv4=%s AND (ip%s_1 %s %s)",
	)

	// 广域网
	tagResourceMap["is_internet"] = NewTag(
		"1",
		"l3_epc_id=-2",
		"",
	)
	// 客户端广域网
	tagResourceMap["is_internet_0"] = NewTag(
		"1",
		"l3_epc_id_0=-2",
		"",
	)
	// 服务端广域网
	tagResourceMap["is_internet_1"] = NewTag(
		"1",
		"l3_epc_id_1=-2",
		"",
	)

	// 掩码
	tagResourceMap["mask_ip"] = NewTag(
		"if(is_ipv4, IPv4NumToString(bitAnd(ip4, %v)), IPv6NumToString(bitAnd(ip6, toFixedString(unhex('%s'), 16))))",
		"",
		"",
	)
	// 客户端掩码
	tagResourceMap["mask_ip_0"] = NewTag(
		"if(is_ipv4, IPv4NumToString(bitAnd(ip4_0, %v)), IPv6NumToString(bitAnd(ip6_0, toFixedString(unhex('%s'), 16))))",
		"",
		"",
	)
	// 服务端掩码
	tagResourceMap["mask_ip_1"] = NewTag(
		"if(is_ipv4, IPv4NumToString(bitAnd(ip4_1, %v)), IPv6NumToString(bitAnd(ip6_1, toFixedString(unhex('%s'), 16))))",
		"",
		"",
	)

	// IP类型
	tagResourceMap["ip_version"] = NewTag(
		"if(is_ipv4=1, 4, 6)",
		"",
		"is_ipv4 %s %s",
	)

	// 是否匹配服务
	tagResourceMap["include_service"] = NewTag(
		"",
		"",
		"is_key_service %s %s",
	)
	return tagResourceMap
}
