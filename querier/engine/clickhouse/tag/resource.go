package tag

import (
	"strconv"

	"metaflow/querier/common"
)

var TagResoureMap = GenerateTagResoureMap()
var DEVICE_MAP = map[string]int{
	"vm":          VIF_DEVICE_TYPE_VM,
	"router":      VIF_DEVICE_TYPE_VROUTER,
	"dhcp_port":   VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         VIF_DEVICE_TYPE_RDS_INSTANCE,
	"lb":          VIF_DEVICE_TYPE_LB,
	"nat_gateway": VIF_DEVICE_TYPE_NAT_GATEWAY,
}

func GenerateTagResoureMap() map[string]map[string]*Tag {
	tagResourceMap := make(map[string]map[string]*Tag)
	// 资源:区域，可用区，容器节点，命名空间，工作负载，容器POD，容器集群，子网
	for _, resourceStr := range TAG_RESOURCE_TYPE_DEFAULT {
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
					resourceIDSuffix+"!=0",
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
				l3EPCIDSuffix+" %s %s",
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
	for resourceStr, deviceTypeValue := range DEVICE_MAP {
		if common.IsValueInSliceString(resourceStr, []string{"pod_service", "nat_gateway", "lb"}) {
			continue
		}
		deviceTypeValueStr := strconv.Itoa(deviceTypeValue)
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			resourceIDSuffix := resourceStr + "_id" + suffix
			deviceIDSuffix := "l3_device_id" + suffix
			deviceTypeSuffix := "l3_device_type" + suffix
			resourceNameSuffix := resourceStr + suffix
			tagResourceMap[resourceIDSuffix] = map[string]*Tag{
				"default": NewTag(
					"if("+deviceTypeSuffix+"="+deviceTypeValueStr+","+deviceIDSuffix+", 0)",
					deviceIDSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					deviceIDSuffix+" %s %s AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"",
				)}
			tagResourceMap[resourceNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"dictGet(deepflow.device_map, ('name'), (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+")))",
					deviceIDSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE name %s %s) AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM deepflow.device_map WHERE %s(name,%s)) AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
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
	for _, autoStr := range TAG_RESOURCE_TYPE_AUTO {
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
				"if(is_ipv4=1, IPv4NumToString("+ip4Suffix+"), IPv6NumToString("+ip6Suffix+")) %s %s",
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
				l3EPCIDSuffix+" %s -2",
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

	// 关联资源
	for _, relatedResourceStr := range []string{"pod_service", "pod_ingress", "nat_gateway", "lb", "lb_listener"} {
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			relatedResourceID := relatedResourceStr + "_id"
			relatedResourceName := relatedResourceStr + "_name"
			relatedResourceIDSuffix := relatedResourceID + suffix
			relatedResourceNameSuffix := relatedResourceStr + suffix
			ip4Suffix := "ip4" + suffix
			ip6Suffix := "ip6" + suffix
			l3EPCIDSuffix := "l3_epc_id" + suffix
			idTagTranslator := ""
			nameTagTranslator := ""
			notNullFilter := ""
			if common.IsValueInSliceString(relatedResourceStr, []string{"pod_service", "nat_gateway", "lb"}) {
				deviceTypeValueStr := strconv.Itoa(DEVICE_MAP[relatedResourceStr])
				deviceIDSuffix := "l3_device_id" + suffix
				deviceTypeSuffix := "l3_device_type" + suffix
				idTagTranslator = "if(" + deviceTypeSuffix + "=" + deviceTypeValueStr + "," + deviceIDSuffix + ", 0)"
				nameTagTranslator = "dictGet(deepflow.device_map, ('name'), (toUInt64(" + deviceTypeValueStr + "),toUInt64(" + deviceIDSuffix + ")))"
				notNullFilter = deviceIDSuffix + "!=0 AND " + deviceTypeSuffix + "=" + deviceTypeValueStr
				tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
					"node_type": NewTag(
						"'"+relatedResourceStr+"'",
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
			tagResourceMap[relatedResourceIDSuffix] = map[string]*Tag{
				"default": NewTag(
					idTagTranslator,
					notNullFilter,
					"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id from deepflow.ip_relation_map WHERE "+relatedResourceID+" %s %s)",
					"",
				)}
			tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
				"default": NewTag(
					nameTagTranslator,
					notNullFilter,
					"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id from deepflow.ip_relation_map WHERE "+relatedResourceName+" %s %s)",
					"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id from deepflow.ip_relation_map WHERE %s("+relatedResourceName+",%s))",
				),
			}
		}
	}
	return tagResourceMap
}
