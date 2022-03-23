package tag

import (
	"errors"
	"fmt"
	"strconv"

	"metaflow/querier/common"
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
		tagResourceMap[resourceStr] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id"},
			resourceStr+"_id",
			resourceStr+"_id !="+notExistID,
			resourceStr+"_id %s %s", // 第一个参数是操作符，第二个参数是过滤的值
		)
		// 资源名称
		tagResourceMap[resourceStr+"_name"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id)))",
			resourceStr+"_id != "+notExistID,
			resourceStr+"_id IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
		// 客户端资源ID
		tagResourceMap[resourceStr+"_0"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_0"},
			resourceStr+"_id_0",
			resourceStr+"_id_0 != "+notExistID,
			resourceStr+"_id_0 %s %s",
		)
		// 客户端资源名称
		tagResourceMap[resourceStr+"_name_0"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_0"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_0)))",
			resourceStr+"_id_0 != "+notExistID,
			resourceStr+"_id_0 IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
		// 服务端资源ID
		tagResourceMap[resourceStr+"_1"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_1"},
			resourceStr+"_id_1",
			resourceStr+"_id_1 != "+notExistID,
			resourceStr+"_id_1 %s %s",
		)
		// 服务端资源名称
		tagResourceMap[resourceStr+"_name_1"] = NewTag(
			[]string{""},
			[]string{resourceStr + "_id_1"},
			"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_1)))",
			resourceStr+"_id_1 != "+notExistID,
			resourceStr+"_id_1 IN (SELECT toUInt16(id) FROM deepflow."+resourceStr+"_map WHERE name %s %s",
		)
	}
	for resourceStr, deviceType := range DeviceMap {
		deviceTypeStr := strconv.Itoa(deviceType)
		// device资源ID
		tagResourceMap[resourceStr] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id", "l3_device_type"},
			"if(l3_device_type="+deviceTypeStr+",l3_device_id, 0)",
			"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
			"l3_device_id %s %s",
		)
		// device资源名称
		tagResourceMap[resourceStr+"_name"] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id", "l3_device_type"},
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id)))",
			"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
			"l3_device_id IN (SELECT toUInt16(deviceid) FROM deepflow.device_map WHERE name %s %s",
		)
		// 客户端device资源ID
		tagResourceMap[resourceStr+"_0"] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id_0", "l3_device_type_0"},
			"if(l3_device_type_0="+deviceTypeStr+",l3_device_id_0, 0)",
			"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
			"l3_device_id_0 %s %s",
		)
		// 客户端device资源名称
		tagResourceMap[resourceStr+"_name_0"] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id_0", "l3_device_type_0"},
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_0)))",
			"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
			"l3_device_id_0 IN (SELECT toUInt16(deviceid) FROM deepflow.device_map WHERE name %s %s",
		)
		// 服务端device资源ID
		tagResourceMap[resourceStr+"_1"] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id_1", "l3_device_type_1"},
			"if(l3_device_type_1="+deviceTypeStr+",l3_device_id_1, 0)",
			"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
			"l3_device_id_1 %s %s",
		)
		// 服务端device资源名称
		tagResourceMap[resourceStr+"_name_1"] = NewTag(
			[]string{"", ""},
			[]string{"l3_device_id_1", "l3_device_type_1"},
			"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_1)))",
			"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
			"l3_device_id_1 IN (SELECT toUInt16(deviceid) FROM deepflow.device_map WHERE name %s %s",
		)
	}

	// IP
	tagResourceMap["ip"] = NewTag(
		[]string{"", "", ""},
		[]string{"ip4", "ip6", "is_ipv4"},
		"if(is_ipv4=1, IPv4NumToString(ip4), IPv6NumToString(ip6))",
		"NOT ((is_ipv4=1 AND (ip4=toIPv4('0.0.0.0'))) OR (is_ipv4=0 AND (ip6=toIPv6('::'))))",
		"is_ipv4=%s AND (ip%s %s %s)",
	)
	// 客户端IP
	tagResourceMap["ip_0"] = NewTag(
		[]string{"", "", ""},
		[]string{"ip4_0", "ip6_0", "is_ipv4"},
		"if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))",
		"NOT ((is_ipv4=1 AND (ip4_0=toIPv4('0.0.0.0'))) OR (is_ipv4=0 AND (ip6_0=toIPv6('::'))))",
		"is_ipv4=%s AND (ip%s_0 %s %s)",
	)
	// 服务端IP
	tagResourceMap["ip_1"] = NewTag(
		[]string{"", "", ""},
		[]string{"ip4_1", "ip6_1", "is_ipv4"},
		"if(is_ipv4=1, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1))",
		"NOT ((is_ipv4=1 AND (ip4_1=toIPv4('0.0.0.0'))) OR (is_ipv4=0 AND (ip6_1=toIPv6('::'))))",
		"is_ipv4=%s AND (ip%s_1 %s %s)",
	)

	// 广域网
	tagResourceMap["is_internet"] = NewTag(
		[]string{""},
		[]string{""},
		"1",
		"l3_epc_id=-2",
		"",
	)
	// 客户端广域网
	tagResourceMap["is_internet_0"] = NewTag(
		[]string{""},
		[]string{""},
		"1",
		"l3_epc_id_0=-2",
		"",
	)
	// 服务端广域网
	tagResourceMap["is_internet_1"] = NewTag(
		[]string{""},
		[]string{""},
		"1",
		"l3_epc_id_1=-2",
		"",
	)
	return tagResourceMap
}
