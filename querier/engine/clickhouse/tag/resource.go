package tag

import (
	"strconv"

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

var AutoMap = map[string]int{
	"vm":          common.VIF_DEVICE_TYPE_VM,
	"router":      common.VIF_DEVICE_TYPE_VROUTER,
	"host":        common.VIF_DEVICE_TYPE_HOST,
	"dhcp_port":   common.VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": common.VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         common.VIF_DEVICE_TYPE_RDS_INSTANCE,
	"pod_node":    common.VIF_DEVICE_TYPE_POD_NODE,
	"lb":          common.VIF_DEVICE_TYPE_LB,
	"nat_gateway": common.VIF_DEVICE_TYPE_NAT_GATEWAY,
}

var AutoPodMap = map[string]int{
	"pod": common.VIF_DEVICE_TYPE_POD,
}

var AutoPodGroupMap = map[string]int{
	"pod_group": common.VIF_DEVICE_TYPE_POD_GROUP,
}

var AutoServiceMap = map[string]int{
	"pod_group": common.VIF_DEVICE_TYPE_POD_GROUP,
	"service":   common.VIF_DEVICE_TYPE_SERVICE,
}

func GenerateTagResoureMap() map[string]map[string]*Tag {
	tagResourceMap := make(map[string]map[string]*Tag)
	// 资源:区域，可用区，容器节点，命名空间，工作负载，容器POD，容器集群，子网
	for _, resourceStr := range []string{"region", "az", "pod_node", "pod_ns", "pod_group", "pod", "pod_cluster", "subnet"} {
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			resourceIDSuffix := resourceStr + "_id" + suffix
			resourceNameSuffix := resourceStr + suffix
			tagResourceMap[resourceIDSuffix] = map[string]*Tag{
				"default": NewTag(
					"",
					resourceIDSuffix+"!=0",
					"",
					"",
				),
			}
			tagResourceMap[resourceNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"dictGet(deepflow."+resourceStr+"_map, ('name'), (toUInt64("+resourceIDSuffix+")))",
					resourceStr+"_id !=0 ",
					"toUInt64("+resourceIDSuffix+") IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE name %s %s)",
					"toUInt64("+resourceIDSuffix+") IN (SELECT id FROM deepflow."+resourceStr+"_map WHERE %s(name,%s))",
				),
				"node_type": NewTag(
					"'"+resourceStr+"'",
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					"dictGet(deepflow."+resourceStr+"_map, ('icon_id'), (toUInt64("+resourceIDSuffix+")))",
					"",
					"",
					"",
				),
			}
		}
	}

	// VPC资源
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		vpcIDSuffix := "vpc_id" + suffix
		l3EPCIDSuffix := "l3_epc_id" + suffix
		vpcNameSuffix := "vpc" + suffix
		tagResourceMap[vpcIDSuffix] = map[string]*Tag{
			"default": NewTag(
				l3EPCIDSuffix,
				l3EPCIDSuffix+"!=-2",
				"",
				"",
			)}
		tagResourceMap[vpcNameSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.l3_epc_map, ('name'), (toUInt64("+l3EPCIDSuffix+")))",
				l3EPCIDSuffix+"!=-2",
				"toUInt64("+l3EPCIDSuffix+") IN (SELECT id FROM deepflow.l3_epc_map WHERE name %s %s)",
				"toUInt64("+l3EPCIDSuffix+") IN (SELECT id FROM deepflow.l3_epc_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'vpc'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.l3_epc_map, ('icon_id'), (toUInt64("+l3EPCIDSuffix+")))",
				"",
				"",
				"",
			),
		}
	}

	// 宿主机
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		hostIDSuffix := "host_id" + suffix
		hostNameSuffix := "host" + suffix
		tagResourceMap[hostIDSuffix] = map[string]*Tag{
			"default": NewTag(
				"",
				hostIDSuffix+"!=0",
				"",
				"",
			)}
		tagResourceMap[hostNameSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(deepflow.device_map, ('name'), (toUInt64(6),toUInt64("+hostIDSuffix+")))",
				hostIDSuffix+"!=0",
				"toUInt64("+hostIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
				"toUInt64("+hostIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'host'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+hostIDSuffix+")))",
				"",
				"",
				"",
			),
		}
	}

	// device资源
	for resourceStr, deviceTypeValue := range DeviceMap {
		deviceTypeValueStr := strconv.Itoa(deviceTypeValue)
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			deviceIDSuffix := "l3_device_id" + suffix
			deviceTypeSuffix := "l3_device_type" + suffix
			deviceNameSuffix := resourceStr + suffix
			tagResourceMap[deviceIDSuffix] = map[string]*Tag{
				"default": NewTag(
					"if("+deviceTypeSuffix+"="+deviceTypeValueStr+","+deviceIDSuffix+", 0)",
					deviceTypeSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					deviceTypeSuffix+" %s %s",
					"",
				)}
			tagResourceMap[deviceNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+")))",
					deviceTypeSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
				),
				"node_type": NewTag(
					"'"+resourceStr+"'",
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+")))",
					"",
					"",
					"",
				),
			}
		}
	}

	// 自动分组
	for _, autoStr := range []string{"resource_gl0", "resource_gl1", "resource_gl2"} {
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			autoIDSuffix := autoStr + "_id" + suffix
			autoTypeSuffix := autoStr + "_type" + suffix
			autoNameSuffix := autoStr + suffix
			nodeTypeStrSuffix := ""
			for nodeType, autoTypeValue := range AutoMap {
				autoTypeValueStr := strconv.Itoa(autoTypeValue)
				nodeTypeStrSuffix = nodeTypeStrSuffix + autoTypeSuffix + "=" + autoTypeValueStr + ",'" + nodeType + "',"
			}
			nodeTypeStrSuffix = nodeTypeStrSuffix + "'ip')"
			switch autoStr {
			case "resource_gl0":
				for nodeType, autoTypeValue := range AutoPodMap {
					autoTypeValueStr := strconv.Itoa(autoTypeValue)
					nodeTypeStrSuffix = autoTypeSuffix + "=" + autoTypeValueStr + ",'" + nodeType + "'," + nodeTypeStrSuffix
				}
			case "resource_gl1":
				for nodeType, autoTypeValue := range AutoPodGroupMap {
					autoTypeValueStr := strconv.Itoa(autoTypeValue)
					nodeTypeStrSuffix = autoTypeSuffix + "=" + autoTypeValueStr + ",'" + nodeType + "'," + nodeTypeStrSuffix
				}
			case "resource_gl2":
				for nodeType, autoTypeValue := range AutoServiceMap {
					autoTypeValueStr := strconv.Itoa(autoTypeValue)
					nodeTypeStrSuffix = autoTypeSuffix + "=" + autoTypeValueStr + ",'" + nodeType + "'," + nodeTypeStrSuffix
				}
			}
			nodeTypeStrSuffix = "multiIf(" + nodeTypeStrSuffix
			tagResourceMap[autoNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"dictGet(deepflow.device_map, ('name'), (toUInt64("+autoTypeSuffix+"),toUInt64("+autoIDSuffix+")))",
					"",
					"toUInt64("+autoIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s)",
					"toUInt64("+autoIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s))",
				),
				"node_type": NewTag(
					nodeTypeStrSuffix,
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					"dictGet(deepflow.device_map, ('icon_id'), (toUInt64("+autoTypeSuffix+"),toUInt64("+autoIDSuffix+")))",
					"",
					"",
					"",
				),
			}
		}
	}

	// IP
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		ipSuffix := "ip" + suffix
		ip4Suffix := "ip4" + suffix
		ip6Suffix := "ip6" + suffix
		tagResourceMap[ipSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(is_ipv4=1, IPv4NumToString("+ip4Suffix+"), IPv6NumToString("+ip6Suffix+"))",
				"",
				"is_ipv4=%s AND (ip%s"+suffix+" %s %s)",
				"",
			), "mask": NewTag(
				"if(is_ipv4, IPv4NumToString(bitAnd("+ip4Suffix+", %v)), IPv6NumToString(bitAnd("+ip6Suffix+", toFixedString(unhex('%s'), 16))))",
				"",
				"",
				"",
			),
			"node_type": NewTag(
				"'ip'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(0),toUInt64(0)))",
				"",
				"",
				"",
			),
		}
	}

	// 广域网
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		isInternetSuffix := "is_internet" + suffix
		l3EPCIDSuffix := "l3_epc_id" + suffix
		tagResourceMap[isInternetSuffix] = map[string]*Tag{
			"default": NewTag(
				"1",
				l3EPCIDSuffix+"=-2",
				"",
				"",
			),
			"node_type": NewTag(
				"'internet'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(deepflow.device_map, ('icon_id'), (toUInt64(63999),toUInt64(63999)))",
				"",
				"",
				"",
			),
		}
	}
	return tagResourceMap
}
