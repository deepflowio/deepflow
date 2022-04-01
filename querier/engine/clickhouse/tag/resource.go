package tag

import (
	"strconv"
	"strings"

	"metaflow/querier/common"
)

var TagResoureMap = GenerateTagResoureMap()

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

func GenerateTagResoureMap() map[string]map[string]*Tag {
	tagResourceMap := make(map[string]map[string]*Tag)
	for _, resourceStr := range []string{"region", "az", "pod_node", "pod_ns", "pod_group", "pod", "pod_cluster", "subnet"} {
		// 资源ID
		notExistID := "0"
		// 资源ID
		tagResourceMap[resourceStr+"_id"] = map[string]*Tag{
			"default": NewTag(
				"",
				resourceStr+"_id !="+notExistID,
				"",
				"",
			),
		}
		// 资源名称
		tagResourceMap[resourceStr] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id)))",
				resourceStr+"_id != "+notExistID,
				"toUInt64("+resourceStr+"_id) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
				"toUInt64("+resourceStr+"_id) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('icon_id'), (toUInt64("+resourceStr+"_id)))",
				"",
				"",
				"",
			),
		}
		// 客户端资源ID
		tagResourceMap[resourceStr+"_id_0"] = map[string]*Tag{
			"default": NewTag(
				"",
				resourceStr+"_id_0 != "+notExistID,
				"",
				"",
			)}
		// 客户端资源名称
		tagResourceMap[resourceStr+"_0"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_0)))",
				resourceStr+"_id_0 != "+notExistID,
				"toUInt64("+resourceStr+"_id_0) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
				"toUInt64("+resourceStr+"_id_0) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('icon_id'), (toUInt64("+resourceStr+"_id_0)))",
				"",
				"",
				"",
			),
		}
		// 服务端资源ID
		tagResourceMap[resourceStr+"_id_1"] = map[string]*Tag{
			"default": NewTag(
				"",
				resourceStr+"_id_1 != "+notExistID,
				"",
				"",
			)}
		// 服务端资源名称
		tagResourceMap[resourceStr+"_1"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceStr+"_id_1)))",
				resourceStr+"_id_1 != "+notExistID,
				"toUInt64("+resourceStr+"_id_1) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
				"toUInt64("+resourceStr+"_id_1) IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow."+resourceStr+"_map, ('icon_id'), (toUInt64("+resourceStr+"_id_1)))",
				"",
				"",
				"",
			),
		}
	}

	// VPC资源ID
	tagResourceMap["vpc_id"] = map[string]*Tag{
		"default": NewTag(
			"l3_epc_id",
			"l3_epc_id != -2",
			"",
			"",
		)}
	// VPC资源名称
	tagResourceMap["vpc"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id)))",
			"l3_epc_id != -2",
			"toUInt64(l3_epc_id) IN (SELECT id FROM deepflow.l3_epc_map WHERE name %s %s)",
			"toUInt64(l3_epc_id) IN (SELECT id FROM deepflow.l3_epc_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'vpc'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.l3_epc_map, ('icon_id'), (toUInt64(l3_epc_id)))",
			"",
			"",
			"",
		),
	}
	// VPC客户端资源ID
	tagResourceMap["vpc_id_0"] = map[string]*Tag{
		"default": NewTag(
			"l3_epc_id_0",
			"l3_epc_id_0 != -2",
			"",
			"",
		)}
	// VPC客户端资源名称
	tagResourceMap["vpc_0"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_0)))",
			"l3_epc_id_0 != -2",
			"toUInt64(l3_epc_id_0) IN (SELECT id FROM deepflow.l3_epc_map WHERE name %s %s)",
			"toUInt64(l3_epc_id_0) IN (SELECT id FROM deepflow.l3_epc_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'vpc'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.l3_epc_map, ('icon_id'), (toUInt64(l3_epc_id_0)))",
			"",
			"",
			"",
		),
	}
	// VPC服务端资源ID
	tagResourceMap["vpc_id_1"] = map[string]*Tag{
		"default": NewTag(
			"l3_epc_id_1",
			"l3_epc_id_1 != -2",
			"",
			"",
		)}
	// VPC服务端资源名称
	tagResourceMap["vpc_1"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_1)))",
			"l3_epc_id_1 != -2",
			"toUInt64(l3_epc_id_1) IN (SELECT id FROM deepflow.l3_epc_map WHERE name %s %s)",
			"toUInt64(l3_epc_id_1) IN (SELECT id FROM deepflow.l3_epc_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'vpc'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.l3_epc_map, ('icon_id'), (toUInt64(l3_epc_id_1)))",
			"",
			"",
			"",
		),
	}

	// 宿主机资源ID
	tagResourceMap["host_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"host_id != 0",
			"",
			"",
		)}
	// 宿主机资源名称
	tagResourceMap["host"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64(6),toUInt64(host_id)))",
			"host_id != 0",
			"toUInt64(host_id) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
			"toUInt64(host_id) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'host'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(host_id)))",
			"",
			"",
			"",
		),
	}
	// 宿主机客户端资源ID
	tagResourceMap["host_id_0"] = map[string]*Tag{
		"default": NewTag(
			"",
			"host_id_0 != 0",
			"",
			"",
		)}
	// 宿主机客户端资源名称
	tagResourceMap["host_0"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64(6),toUInt64(host_id_0)))",
			"host_id_0 != 0",
			"toUInt64(host_id_0) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
			"toUInt64(host_id_0) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'host'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(host_id_0)))",
			"",
			"",
			"",
		),
	}
	// 宿主机服务端资源ID
	tagResourceMap["host_id_1"] = map[string]*Tag{
		"default": NewTag(
			"",
			"host_id_1 != 0",
			"",
			"",
		)}
	// 宿主机服务端资源名称
	tagResourceMap["host_1"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(deepflow.device_map, ('name'), (toUInt64(6),toUInt64(host_id_1)))",
			"host_id_1 != 0",
			"toUInt64(host_id_1) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
			"toUInt64(host_id_1) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
		),
		"node_type": NewTag(
			"'host'",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(host_id_1)))",
			"",
			"",
			"",
		),
	}

	for resourceStr, deviceType := range DeviceMap {
		deviceTypeStr := strconv.Itoa(deviceType)
		// device资源ID
		tagResourceMap[resourceStr+"_id"] = map[string]*Tag{
			"default": NewTag(
				"if(l3_device_type="+deviceTypeStr+",l3_device_id, 0)",
				"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
				"l3_device_id %s %s",
				"",
			)}
		// device资源名称
		tagResourceMap[resourceStr] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id)))",
				"l3_device_id != 0 AND l3_device_type = "+deviceTypeStr,
				"toUInt64(l3_device_id) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64(l3_device_id) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id)))",
				"",
				"",
				"",
			),
		}
		// 客户端device资源ID
		tagResourceMap[resourceStr+"_id_0"] = map[string]*Tag{
			"default": NewTag(
				"if(l3_device_type_0="+deviceTypeStr+",l3_device_id_0, 0)",
				"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
				"l3_device_id_0 %s %s",
				"",
			)}
		// 客户端device资源名称
		tagResourceMap[resourceStr+"_0"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_0)))",
				"l3_device_id_0 != 0 AND l3_device_type_0 = "+deviceTypeStr,
				"toUInt64(l3_device_id_0) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64(l3_device_id_0) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_0)))",
				"",
				"",
				"",
			),
		}
		// 服务端device资源ID
		tagResourceMap[resourceStr+"_id_1"] = map[string]*Tag{
			"default": NewTag(
				"if(l3_device_type_1="+deviceTypeStr+",l3_device_id_1, 0)",
				"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
				"l3_device_id_1 %s %s",
				"",
			)}
		// 服务端device资源名称
		tagResourceMap[resourceStr+"_1"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_1)))",
				"l3_device_id_1 != 0 AND l3_device_type_1 = "+deviceTypeStr,
				"toUInt64(l3_device_id_1) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64(l3_device_id_1) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'"+resourceStr+"'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+deviceTypeStr+"),toUInt64(l3_device_id_1)))",
				"",
				"",
				"",
			),
		}
	}

	for _, autoStr := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
		autoID := autoStr + "_id"
		autoType := autoStr + "_type"
		autoTypeClient := autoStr + "_type_0"
		autoTypeServer := autoStr + "_type_1"
		nodeTypeStr := autoType + "=1,'vm'," + autoType + "=5,'router'," + autoType + "=6,'host'," +
			autoType + "=9,'dhcp_port'," + autoType + "=10,'pod'," + autoType + "=11,'pod_service'," +
			autoType + "=12,'redis'," + autoType + "=13,'rds'," + autoType + "=14,'pod_node'," +
			autoType + "=15,'lb'," + autoType + "=16,'nat_gateway','ip')"
		nodeTypeStrClient := strings.ReplaceAll(nodeTypeStr, autoType, autoTypeClient)
		nodeTypeStrServer := strings.ReplaceAll(nodeTypeStr, autoType, autoTypeServer)
		switch autoStr {
		case "resource_gl0":
			nodeTypeStr = "multiIf(" + nodeTypeStr
			nodeTypeStrClient = "multiIf(" + nodeTypeStrClient
			nodeTypeStrServer = "multiIf(" + nodeTypeStrServer
		case "resource_gl1":
			nodeTypeStr = "multiIf(" + autoType + "=101,'pod_group'," + nodeTypeStr
			nodeTypeStrClient = "multiIf(" + autoTypeClient + "=101,'pod_group'," + nodeTypeStrClient
			nodeTypeStrServer = "multiIf(" + autoTypeServer + "=101,'pod_group'," + nodeTypeStrServer
		case "resource_gl2":
			nodeTypeStr = "multiIf(" + autoType + "=101,'pod_group'," + autoType + "=102,'service'," + nodeTypeStr
			nodeTypeStrClient = "multiIf(" + autoTypeClient + "=101,'pod_group'," + autoTypeClient + "=102,'service'," + nodeTypeStrClient
			nodeTypeStrServer = "multiIf(" + autoTypeServer + "=101,'pod_group'," + autoTypeServer + "=102,'service'," + nodeTypeStrServer
		}
		// 自动分组资源名称
		tagResourceMap[autoStr] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"),toUInt64("+autoID+")))",
				"",
				"toUInt64("+autoID+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64("+autoID+") IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				nodeTypeStr,
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+autoType+"),toUInt64("+autoID+")))",
				"",
				"",
				"",
			),
		}
		// 自动分组客户端资源名称
		tagResourceMap[autoStr+"_0"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"_0),toUInt64("+autoID+"_0)))",
				"",
				"toUInt64("+autoID+"_0) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64("+autoID+"_0) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				nodeTypeStrClient,
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+autoType+"_0),toUInt64("+autoID+"_0)))",
				"",
				"",
				"",
			),
		}
		// 自动分组服务端资源名称
		tagResourceMap[autoStr+"_1"] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoType+"_1),toUInt64("+autoID+"_1)))",
				"",
				"toUInt64("+autoID+"_1) IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64("+autoID+"_1) IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				nodeTypeStrServer,
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+autoType+"_1),toUInt64("+autoID+"_1)))",
				"",
				"",
				"",
			),
		}
	}

	// IP
	ipNodeType := NewTag(
		"'ip'",
		"",
		"",
		"",
	)
	ipIconID := NewTag(
		"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(0),toUInt64(0)))",
		"",
		"",
		"",
	)
	tagResourceMap["ip"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, IPv4NumToString(ip4), IPv6NumToString(ip6))",
			"",
			"is_ipv4=%s AND (ip%s %s %s)",
			"",
		), "mask": NewTag(
			"if(is_ipv4, IPv4NumToString(bitAnd(ip4, %v)), IPv6NumToString(bitAnd(ip6, toFixedString(unhex('%s'), 16))))",
			"",
			"",
			"",
		),
		"node_type": ipNodeType,
		"icon_id":   ipIconID,
	}
	// 客户端IP
	tagResourceMap["ip_0"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))",
			"",
			"is_ipv4=%s AND (ip%s_0 %s %s)",
			"",
		), "mask": NewTag(
			"if(is_ipv4, IPv4NumToString(bitAnd(ip4_0, %v)), IPv6NumToString(bitAnd(ip6_0, toFixedString(unhex('%s'), 16))))",
			"",
			"",
			"",
		),
		"node_type": ipNodeType,
		"icon_id":   ipIconID,
	}
	// 服务端IP
	tagResourceMap["ip_1"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1))",
			"",
			"is_ipv4=%s AND (ip%s_1 %s %s)",
			"",
		), "mask": NewTag(
			"if(is_ipv4, IPv4NumToString(bitAnd(ip4_1, %v)), IPv6NumToString(bitAnd(ip6_1, toFixedString(unhex('%s'), 16))))",
			"",
			"",
			"",
		),
		"node_type": ipNodeType,
		"icon_id":   ipIconID,
	}

	// 广域网
	internetNodeType := NewTag(
		"'internet'",
		"",
		"",
		"",
	)
	internetIconID := NewTag(
		"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(63999),toUInt64(63999)))",
		"",
		"",
		"",
	)
	tagResourceMap["is_internet"] = map[string]*Tag{
		"default": NewTag(
			"1",
			"l3_epc_id=-2",
			"",
			"",
		),
		"node_type": internetNodeType,
		"icon_id":   internetIconID,
	}
	// 客户端广域网
	tagResourceMap["is_internet_0"] = map[string]*Tag{
		"default": NewTag(
			"1",
			"l3_epc_id_0=-2",
			"",
			"",
		),
		"node_type": internetNodeType,
		"icon_id":   internetIconID,
	}
	// 服务端广域网
	tagResourceMap["is_internet_1"] = map[string]*Tag{
		"default": NewTag(
			"1",
			"l3_epc_id_1=-2",
			"",
			"",
		),
		"node_type": internetNodeType,
		"icon_id":   internetIconID,
	}
	return tagResourceMap
}
