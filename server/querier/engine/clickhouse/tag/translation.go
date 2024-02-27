/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tag

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/querier/common"
)

var TagResoureMap = GenerateTagResoureMap()
var FlowTagResourceMap = GenerateFlowTagTagResoureMap()
var DEVICE_MAP = map[string]int{
	"chost":       VIF_DEVICE_TYPE_VM,
	"router":      VIF_DEVICE_TYPE_VROUTER,
	"dhcpgw":      VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         VIF_DEVICE_TYPE_RDS_INSTANCE,
	"lb":          VIF_DEVICE_TYPE_LB,
	"natgw":       VIF_DEVICE_TYPE_NAT_GATEWAY,
}
var TAP_PORT_DEVICE_MAP = map[string]int{
	common.TAP_PORT_HOST:        VIF_DEVICE_TYPE_HOST,
	common.TAP_PORT_CHOST:       VIF_DEVICE_TYPE_VM,
	common.TAP_PORT_POD_NODE:    VIF_DEVICE_TYPE_POD_NODE,
	common.CAPTURE_NIC_HOST:     VIF_DEVICE_TYPE_HOST,
	common.CAPTURE_NIC_CHOST:    VIF_DEVICE_TYPE_VM,
	common.CAPTURE_NIC_POD_NODE: VIF_DEVICE_TYPE_POD_NODE,
}
var HOSTNAME_IP_DEVICE_MAP = map[string]struct {
	ResourceType int
	ResourceName string
	FieldName    string
}{
	common.HOST_HOSTNAME:     {ResourceType: VIF_DEVICE_TYPE_HOST, ResourceName: "host", FieldName: "hostname"},
	common.HOST_IP:           {ResourceType: VIF_DEVICE_TYPE_HOST, ResourceName: "host", FieldName: "ip"},
	common.CHOST_HOSTNAME:    {ResourceType: VIF_DEVICE_TYPE_VM, ResourceName: "chost", FieldName: "hostname"},
	common.CHOST_IP:          {ResourceType: VIF_DEVICE_TYPE_VM, ResourceName: "chost", FieldName: "ip"},
	common.POD_NODE_HOSTNAME: {ResourceType: VIF_DEVICE_TYPE_POD_NODE, ResourceName: "pod_node", FieldName: "hostname"},
	common.POD_NODE_IP:       {ResourceType: VIF_DEVICE_TYPE_POD_NODE, ResourceName: "pod_node", FieldName: "ip"},
}

var INT_ENUM_TAG = []string{"close_type", "eth_type", "signal_source", "is_ipv4", "l7_ip_protocol", "type", "l7_protocol", "protocol", "response_status", "server_port", "status", "capture_nic_type", "tunnel_tier", "tunnel_type", "instance_type", "nat_source", "role", "event_level", "policy_level", "policy_app_type", "is_tls"}
var INT_ENUM_PEER_TAG = []string{"resource_gl0_type", "resource_gl1_type", "resource_gl2_type", "tcp_flags_bit", "auto_instance_type", "auto_service_type"}
var STRING_ENUM_TAG = []string{"observation_point", "event_type", "profile_language_type"}

func GenerateTagResoureMap() map[string]map[string]*Tag {
	tagResourceMap := make(map[string]map[string]*Tag)
	// 资源:区域，可用区，容器节点，命名空间，工作负载，容器POD，容器集群，子网
	for _, resourceStr := range TAG_RESOURCE_TYPE_DEFAULT {
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			resourceIDSuffix := resourceStr + "_id" + suffix
			resourceNameSuffix := resourceStr + suffix
			groupNotNullFilter := ""
			if !slices.Contains[[]string, string]([]string{"region", "az", "subnet", "pod_cluster"}, resourceStr) {
				groupNotNullFilter = resourceIDSuffix + "!=0"
			}
			tagResourceMap[resourceIDSuffix] = map[string]*Tag{
				"default": NewTag(
					"",
					groupNotNullFilter,
					"",
					"",
				),
			}
			tagResourceMap[resourceNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"dictGet(flow_tag."+resourceStr+"_map, 'name', (toUInt64("+resourceIDSuffix+")))",
					groupNotNullFilter,
					"toUInt64("+resourceIDSuffix+") IN (SELECT id FROM flow_tag."+resourceStr+"_map WHERE name %s %s)",
					"toUInt64("+resourceIDSuffix+") IN (SELECT id FROM flow_tag."+resourceStr+"_map WHERE %s(name,%s))",
				),
				"node_type": NewTag(
					"'"+resourceStr+"'",
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					"dictGet(flow_tag."+resourceStr+"_map, 'icon_id', (toUInt64("+resourceIDSuffix+")))",
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
		// l3_epc
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
				"dictGet(flow_tag.l3_epc_map, 'name', (toUInt64("+l3EPCIDSuffix+")))",
				l3EPCIDSuffix+"!=-2",
				"toUInt64("+l3EPCIDSuffix+") IN (SELECT id FROM flow_tag.l3_epc_map WHERE name %s %s)",
				"toUInt64("+l3EPCIDSuffix+") IN (SELECT id FROM flow_tag.l3_epc_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'vpc'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(flow_tag.l3_epc_map, 'icon_id', (toUInt64("+l3EPCIDSuffix+")))",
				"",
				"",
				"",
			),
		}
		// l2_epc
		l2VpcIDSuffix := "l2_vpc_id" + suffix
		l2EPCIDSuffix := "epc_id" + suffix
		l2VpcNameSuffix := "l2_vpc" + suffix
		tagResourceMap[l2VpcIDSuffix] = map[string]*Tag{
			"default": NewTag(
				l2EPCIDSuffix,
				l2EPCIDSuffix+"!=-2",
				l2EPCIDSuffix+" %s %s",
				"",
			)}
		tagResourceMap[l2VpcNameSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.l3_epc_map, 'name', (toUInt64("+l2EPCIDSuffix+")))",
				l2EPCIDSuffix+"!=0",
				"toUInt64("+l2EPCIDSuffix+") IN (SELECT id FROM flow_tag.l3_epc_map WHERE name %s %s)",
				"toUInt64("+l2EPCIDSuffix+") IN (SELECT id FROM flow_tag.l3_epc_map WHERE %s(name,%s))",
			),
			"node_type": NewTag(
				"'l2_vpc'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(flow_tag.l3_epc_map, 'icon_id', (toUInt64("+l2EPCIDSuffix+")))",
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
				"dictGet(flow_tag.device_map, 'name', (toUInt64(6),toUInt64("+hostIDSuffix+")))",
				hostIDSuffix+"!=0",
				"toUInt64("+hostIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE name %s %s AND devicetype=6)",
				"toUInt64("+hostIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE %s(name,%s) AND devicetype=6)",
			),
			"node_type": NewTag(
				"'host'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(flow_tag.device_map, 'icon_id', (toUInt64(6),toUInt64("+hostIDSuffix+")))",
				"",
				"",
				"",
			),
		}
	}

	// 服务
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	// service
	// The following tag definitions generate name and ID for single-ended/double-ended -0-ended/double-ended-1-ended respectively
	for _, suffix := range []string{"", "_0", "_1"} {
		serviceIDSuffix := "service_id" + suffix
		serviceNameSuffix := "service" + suffix
		tagResourceMap[serviceIDSuffix] = map[string]*Tag{
			"default": NewTag(
				"",
				serviceIDSuffix+"!=0",
				"",
				"",
			)}
		tagResourceMap[serviceNameSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.device_map, 'name', (toUInt64(11),toUInt64("+serviceIDSuffix+")))",
				serviceIDSuffix+"!=0",
				"toUInt64("+serviceIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE name %s %s AND devicetype=11)",
				"toUInt64("+serviceIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE %s(name,%s) AND devicetype=11)",
			),
			"node_type": NewTag(
				"'service'",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"dictGet(flow_tag.device_map, 'icon_id', (toUInt64(11),toUInt64("+serviceIDSuffix+")))",
				"",
				"",
				"",
			),
		}
	}

	// device资源
	for resourceStr, deviceTypeValue := range DEVICE_MAP {
		if common.IsValueInSliceString(resourceStr, []string{"pod_service", "natgw", "lb"}) {
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
					"if("+deviceTypeSuffix+"="+deviceTypeValueStr+", dictGet(flow_tag.device_map, 'name', (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+"))), '')",
					deviceIDSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE name %s %s AND devicetype="+deviceTypeValueStr+") AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					"toUInt64("+deviceIDSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE %s(name,%s) AND devicetype="+deviceTypeValueStr+") AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
				),
				"node_type": NewTag(
					"'"+resourceStr+"'",
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					"if("+deviceTypeSuffix+"="+deviceTypeValueStr+", dictGet(flow_tag.device_map, 'icon_id', (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+"))), 0)",
					"",
					"",
					"",
				),
			}
		}
	}

	// 采集器名称
	tagResourceMap["vtap"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(flow_tag.vtap_map, 'name', toUInt64(agent_id))",
			"",
			"toUInt64(agent_id) IN (SELECT id FROM flow_tag.vtap_map WHERE name %s %s)",
			"toUInt64(agent_id) IN (SELECT id FROM flow_tag.vtap_map WHERE %s(name,%s))",
		),
	}
	tagResourceMap["agent"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(flow_tag.vtap_map, 'name', toUInt64(agent_id))",
			"",
			"toUInt64(agent_id) IN (SELECT id FROM flow_tag.vtap_map WHERE name %s %s)",
			"toUInt64(agent_id) IN (SELECT id FROM flow_tag.vtap_map WHERE %s(name,%s))",
		),
	}
	// 采集器名称ID
	tagResourceMap["vtap_id"] = map[string]*Tag{
		"default": NewTag(
			"agent_id",
			"",
			"agent_id %s %s",
			"",
		),
	}

	// 自动分组
	for _, autoStr := range TAG_RESOURCE_TYPE_AUTO {
		// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
		for _, suffix := range []string{"", "_0", "_1"} {
			tagAutoIDSuffix := autoStr + "_id" + suffix
			tagAutoTypeSuffix := autoStr + "_type" + suffix
			autoIDSuffix := "auto_service_id" + suffix
			autoTypeSuffix := "auto_service_type" + suffix
			if common.IsValueInSliceString(autoStr, []string{"resource_gl0", "auto_instance"}) {
				autoTypeSuffix = "auto_instance_type" + suffix
				autoIDSuffix = "auto_instance_id" + suffix
			}
			autoNameSuffix := autoStr + suffix
			ip4Suffix := "ip4" + suffix
			ip6Suffix := "ip6" + suffix
			subnetIDSuffix := "subnet_id" + suffix
			nodeTypeStrSuffix := "dictGet(flow_tag.node_type_map, 'node_type', toUInt64(" + autoTypeSuffix + "))"
			internetIconDictGet := "dictGet(flow_tag.device_map, 'icon_id', (toUInt64(63999),toUInt64(63999)))"
			ipIconDictGet := "dictGet(flow_tag.device_map, 'icon_id', (toUInt64(64000),toUInt64(64000)))"
			autoIconDictGet := fmt.Sprintf("dictGet(flow_tag.device_map, 'icon_id', (toUInt64(%s),toUInt64(%s)))", autoTypeSuffix, autoIDSuffix)
			iconIDStrSuffix := fmt.Sprintf("multiIf(%s=%d,%s,%s=%d,%s,%s)", autoTypeSuffix, VIF_DEVICE_TYPE_INTERNET, internetIconDictGet, autoTypeSuffix, VIF_DEVICE_TYPE_IP, ipIconDictGet, autoIconDictGet)
			deviceTypeFilter := ""
			if strings.HasPrefix(autoNameSuffix, "resource_gl0") || strings.HasPrefix(autoNameSuffix, "auto_instance") {
				deviceTypeFilter = "devicetype not in (101,102)"
			} else {
				deviceTypeFilter = "devicetype not in (10)"
			}
			tagResourceMap[autoNameSuffix] = map[string]*Tag{
				"default": NewTag(
					"if("+autoTypeSuffix+" in (0,255),if(is_ipv4=1, IPv4NumToString("+ip4Suffix+"), IPv6NumToString("+ip6Suffix+")),dictGet(flow_tag.device_map, 'name', (toUInt64("+autoTypeSuffix+"),toUInt64("+autoIDSuffix+"))))",
					"",
					"if("+autoTypeSuffix+" in (0,255),if(is_ipv4=1, IPv4NumToString("+ip4Suffix+"), IPv6NumToString("+ip6Suffix+")) %s %s,(toUInt64("+autoIDSuffix+"),toUInt64("+autoTypeSuffix+")) IN (SELECT deviceid,devicetype FROM flow_tag.device_map WHERE name %s %s AND "+deviceTypeFilter+"))",
					"if("+autoTypeSuffix+" in (0,255),%s(if(is_ipv4=1, IPv4NumToString("+ip4Suffix+"), IPv6NumToString("+ip6Suffix+")),%s),(toUInt64("+autoIDSuffix+"),toUInt64("+autoTypeSuffix+")) IN (SELECT deviceid,devicetype FROM flow_tag.device_map WHERE %s(name,%s) AND "+deviceTypeFilter+"))",
				),
				"node_type": NewTag(
					nodeTypeStrSuffix,
					"",
					"",
					"",
				),
				"icon_id": NewTag(
					iconIDStrSuffix,
					"",
					"",
					"",
				),
			}
			tagResourceMap[tagAutoIDSuffix] = map[string]*Tag{
				"default": NewTag(
					"if("+autoTypeSuffix+" in (0,255),"+subnetIDSuffix+","+autoIDSuffix+")",
					"",
					"if("+autoTypeSuffix+" in (0,255),"+subnetIDSuffix+" %s %s,"+autoIDSuffix+" %s %s)",
					"",
				),
			}
			if strings.HasPrefix(tagAutoTypeSuffix, "auto") {
				continue
			}
			tagResourceMap[tagAutoTypeSuffix] = map[string]*Tag{
				"default": NewTag(
					autoTypeSuffix,
					"",
					autoTypeSuffix+" %s %s",
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
				"if(is_ipv4=1, hex("+ip4Suffix+"), hex("+ip6Suffix+")) %s %s",
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
				"dictGet(flow_tag.device_map, 'icon_id', (toUInt64(64000),toUInt64(64000)))",
				"",
				"",
				"",
			),
		}
	}

	// Instance-event
	tagResourceMap["instance"] = map[string]*Tag{
		"default": NewTag(
			"instance_name",
			"",
			"instance_name %s %s",
			"%s(instance_name,%s)",
		),
		"node_type": NewTag(
			"dictGet(flow_tag.node_type_map, 'node_type', toUInt64(instance_type))",
			"",
			"",
			"",
		),
		"icon_id": NewTag(
			"dictGet(flow_tag.device_map, 'icon_id', (toUInt64(instance_type),toUInt64(instance_id)))",
			"",
			"",
			"",
		),
	}
	// Time-event
	tagResourceMap["time_str"] = map[string]*Tag{
		"default": NewTag(
			"toString(time)",
			"",
			"",
			"",
		),
	}

	// 广域网
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		isInternetSuffix := "is_internet" + suffix
		l3EPCIDSuffix := "l3_epc_id" + suffix
		tagResourceMap[isInternetSuffix] = map[string]*Tag{
			"default": NewTag(
				"if("+l3EPCIDSuffix+"=-2,1,0)",
				"",
				l3EPCIDSuffix+" %s -2",
				"",
			),
			"node_type": NewTag(
				"if("+l3EPCIDSuffix+"=-2,'internet','')",
				"",
				"",
				"",
			),
			"icon_id": NewTag(
				"if("+l3EPCIDSuffix+"=-2,dictGet(flow_tag.device_map, 'icon_id', (toUInt64(63999),toUInt64(63999))),0)",
				"",
				"",
				"",
			),
		}
	}

	// 关联资源
	for _, relatedResourceStr := range []string{"pod_service", "pod_ingress", "natgw", "lb", "lb_listener"} {
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
			deviceIDSuffix := "l3_device_id" + suffix
			serviceIDSuffix := "service_id" + suffix
			deviceTypeSuffix := "l3_device_type" + suffix
			deviceTypeValueStr := strconv.Itoa(DEVICE_MAP[relatedResourceStr])
			if common.IsValueInSliceString(relatedResourceStr, []string{"natgw", "lb"}) {
				idTagTranslator = "if(" + deviceTypeSuffix + "=" + deviceTypeValueStr + "," + deviceIDSuffix + ", 0)"
				nameTagTranslator = "if(" + deviceTypeSuffix + "=" + deviceTypeValueStr + ", dictGet(flow_tag.device_map, 'name', (toUInt64(" + deviceTypeValueStr + "),toUInt64(" + deviceIDSuffix + "))), '')"
				notNullFilter = deviceIDSuffix + "!=0 AND " + deviceTypeSuffix + "=" + deviceTypeValueStr
				tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
					"node_type": NewTag(
						"'"+relatedResourceStr+"'",
						"",
						"",
						"",
					),
					"icon_id": NewTag(
						"if("+deviceTypeSuffix+"="+deviceTypeValueStr+", dictGet(flow_tag.device_map, 'icon_id', (toUInt64("+deviceTypeValueStr+"),toUInt64("+deviceIDSuffix+"))), 0)",
						"",
						"",
						"",
					),
					"default": NewTag(
						nameTagTranslator,
						notNullFilter,
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s)",
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s))",
					),
				}
				tagResourceMap[relatedResourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						idTagTranslator,
						notNullFilter,
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceID+" %s %s)",
						"",
					),
				}
			} else if relatedResourceStr == "pod_service" {
				nameTagTranslator = "dictGet(flow_tag.device_map, 'name', (toUInt64(" + deviceTypeValueStr + "),toUInt64(" + serviceIDSuffix + ")))"
				notNullFilter = serviceIDSuffix + "!=0"
				tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
					"node_type": NewTag(
						"'"+relatedResourceStr+"'",
						"",
						"",
						"",
					),
					"icon_id": NewTag(
						"dictGet(flow_tag.device_map, 'icon_id', (toUInt64("+deviceTypeValueStr+"),toUInt64("+serviceIDSuffix+")))",
						"",
						"",
						"",
					),
					"default": NewTag(
						nameTagTranslator,
						notNullFilter,
						"((if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s)) OR (toUInt64(service_id"+suffix+") IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s))",
						"((if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s))) OR (toUInt64(service_id"+suffix+") IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s)))",
					),
				}
				tagResourceMap[relatedResourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						serviceIDSuffix,
						notNullFilter,
						"service_id"+suffix+" %s %s",
						"",
					),
				}
			} else if relatedResourceStr == "pod_ingress" {
				// pod_ingress关联资源包含pod_service
				deviceTypeValueStr = strconv.Itoa(VIF_DEVICE_TYPE_POD_SERVICE)
				tagResourceMap[relatedResourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						"",
						"",
						"((if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceID+" %s %s)) OR (toUInt64(service_id"+suffix+") IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceID+" %s %s))",
						"",
					),
				}
				tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
					"default": NewTag(
						"",
						"",
						"((if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s)) OR (toUInt64(service_id"+suffix+") IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s))",
						"((if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s))) OR (toUInt64(service_id"+suffix+") IN (SELECT pod_service_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s)))",
					),
				}
			} else {
				tagResourceMap[relatedResourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						"",
						"",
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceID+" %s %s)",
						"",
					),
				}
				tagResourceMap[relatedResourceNameSuffix] = map[string]*Tag{
					"default": NewTag(
						"",
						"",
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE "+relatedResourceName+" %s %s)",
						"(if(is_ipv4=1,IPv4NumToString("+ip4Suffix+"),IPv6NumToString("+ip6Suffix+")),toUInt64("+l3EPCIDSuffix+")) IN (SELECT ip,l3_epc_id FROM flow_tag.ip_relation_map WHERE %s("+relatedResourceName+",%s))",
					),
				}
			}
		}
	}

	// vtap对应资源
	vtapResource := "'device_type','device_id','device_name','icon_id','host_id','host_name'"
	gwDictGet := fmt.Sprintf("dictGet(flow_tag.vtap_port_map, (%s),(toUInt64(agent_id),toUInt64(capture_nic)))", vtapResource)
	tagResourceMap["resource_from_vtap"] = map[string]*Tag{
		"default": NewTag(
			gwDictGet,
			"",
			"",
			"",
		),
	}

	// K8s Labels
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		k8sLabelSuffix := "k8s_label" + suffix
		podIDSuffix := "pod_id" + suffix
		serviceIDSuffix := "service_id" + suffix
		tagResourceMap[k8sLabelSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64("+serviceIDSuffix+"),'%s'))!='', dictGet(flow_tag.pod_service_k8s_label_map, 'value', (toUInt64("+serviceIDSuffix+"),'%s')), dictGet(flow_tag.pod_k8s_label_map, 'value', (toUInt64("+podIDSuffix+"),'%s')) )",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE key='%s')))",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE value %s %s and key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE value %s %s and key='%s')))",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_label_map WHERE %s(value,%s) and key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_label_map WHERE %s(value,%s) and key='%s')))",
			),
		}
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		k8sLabelSuffix := "k8s.label" + suffix
		podIDSuffix := "pod_id" + suffix
		serviceIDSuffix := "service_id" + suffix
		tagResourceMap[k8sLabelSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(dictGetOrDefault(flow_tag.pod_service_k8s_labels_map, 'labels', toUInt64("+serviceIDSuffix+"),'{}')!='{}', dictGetOrDefault(flow_tag.pod_service_k8s_labels_map, 'labels', toUInt64("+serviceIDSuffix+"),'{}'), dictGetOrDefault(flow_tag.pod_k8s_labels_map, 'labels', toUInt64("+podIDSuffix+"),'{}')) ",
				"("+serviceIDSuffix+"!=0 OR "+podIDSuffix+"!=0)",
				"",
				"",
			),
		}
	}

	// K8s annotations
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		k8sAnnotationSuffix := "k8s_annotation" + suffix
		podIDSuffix := "pod_id" + suffix
		serviceIDSuffix := "service_id" + suffix
		tagResourceMap[k8sAnnotationSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64("+serviceIDSuffix+"),'%s'))!='', dictGet(flow_tag.pod_service_k8s_annotation_map, 'value', (toUInt64("+serviceIDSuffix+"),'%s')), dictGet(flow_tag.pod_k8s_annotation_map, 'value', (toUInt64("+podIDSuffix+"),'%s')) )",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE key='%s')))",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE value %s %s and key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE value %s %s and key='%s')))",
				"((toUInt64("+serviceIDSuffix+") IN (SELECT id FROM flow_tag.pod_service_k8s_annotation_map WHERE %s(value,%s) and key='%s')) OR (toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_annotation_map WHERE %s(value,%s) and key='%s')))",
			),
		}
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		k8sAnnotationSuffix := "k8s.annotation" + suffix
		podIDSuffix := "pod_id" + suffix
		serviceIDSuffix := "service_id" + suffix
		tagResourceMap[k8sAnnotationSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(dictGetOrDefault(flow_tag.pod_service_k8s_annotations_map, 'annotations', toUInt64("+serviceIDSuffix+"),'{}')!='{}', dictGetOrDefault(flow_tag.pod_service_k8s_annotations_map, 'annotations', toUInt64("+serviceIDSuffix+"),'{}'), dictGetOrDefault(flow_tag.pod_k8s_annotations_map, 'annotations', toUInt64("+podIDSuffix+"),'{}')) ",
				"("+serviceIDSuffix+"!=0 OR "+podIDSuffix+"!=0)",
				"",
				"",
			),
		}
	}

	// K8s envs
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		k8senvSuffix := "k8s_env" + suffix
		podIDSuffix := "pod_id" + suffix
		tagResourceMap[k8senvSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.pod_k8s_env_map, 'value', (toUInt64("+podIDSuffix+"),'%s'))",
				"toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE key='%s')",
				"toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE value %s %s and key='%s')",
				"toUInt64("+podIDSuffix+") IN (SELECT id FROM flow_tag.pod_k8s_env_map WHERE %s(value,%s) and key='%s')",
			),
		}
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		k8senvSuffix := "k8s.env" + suffix
		podIDSuffix := "pod_id" + suffix
		tagResourceMap[k8senvSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGetOrDefault(flow_tag.pod_k8s_envs_map, 'envs', toUInt64("+podIDSuffix+"),'{}') ",
				podIDSuffix+"!=0",
				"",
				"",
			),
		}
	}

	// cloud tags
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		cloudTagSuffix := "cloud_tag" + suffix
		deviceIDSuffix := "l3_device_id" + suffix
		deviceTypeIDSuffix := "l3_device_type" + suffix
		podNSIDSuffix := "pod_ns_id" + suffix
		tagResourceMap[cloudTagSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(if("+deviceTypeIDSuffix+"=1, dictGet(flow_tag.chost_cloud_tag_map, 'value', (toUInt64("+deviceIDSuffix+"),'%s')), '')!='',if("+deviceTypeIDSuffix+"=1, dictGet(flow_tag.chost_cloud_tag_map, 'value', (toUInt64("+deviceIDSuffix+"),'%s')), ''), dictGet(flow_tag.pod_ns_cloud_tag_map, 'value', (toUInt64("+podNSIDSuffix+"),'%s')) )",
				"((toUInt64("+deviceIDSuffix+") IN (SELECT id FROM flow_tag.chost_cloud_tag_map WHERE key='%s') AND "+deviceTypeIDSuffix+"=1) OR (toUInt64("+podNSIDSuffix+") IN (SELECT id FROM flow_tag.pod_ns_cloud_tag_map WHERE key='%s')))",
				"((toUInt64("+deviceIDSuffix+") IN (SELECT id FROM flow_tag.chost_cloud_tag_map WHERE value %s %s and key='%s') AND "+deviceTypeIDSuffix+"=1) OR (toUInt64("+podNSIDSuffix+") IN (SELECT id FROM flow_tag.pod_ns_cloud_tag_map WHERE value %s %s and key='%s'))) ",
				"((toUInt64("+deviceIDSuffix+") IN (SELECT id FROM flow_tag.chost_cloud_tag_map WHERE %s(value,%s) and key='%s') AND "+deviceTypeIDSuffix+"=1) OR (toUInt64("+podNSIDSuffix+") IN (SELECT id FROM flow_tag.pod_ns_cloud_tag_map WHERE %s(value,%s) and key='%s'))) ",
			),
		}
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		cloudTagSuffix := "cloud.tag" + suffix
		deviceIDSuffix := "l3_device_id" + suffix
		deviceTypeIDSuffix := "l3_device_type" + suffix
		podNSIDSuffix := "pod_ns_id" + suffix
		tagResourceMap[cloudTagSuffix] = map[string]*Tag{
			"default": NewTag(
				"if(if("+deviceTypeIDSuffix+"=1, dictGetOrDefault(flow_tag.chost_cloud_tags_map, 'cloud_tags', toUInt64("+deviceIDSuffix+"),'{}'), '{}')!='{}',if("+deviceTypeIDSuffix+"=1, dictGetOrDefault(flow_tag.chost_cloud_tags_map, 'cloud_tags', toUInt64("+deviceIDSuffix+"),'{}'), '{}'), dictGetOrDefault(flow_tag.pod_ns_cloud_tags_map, 'cloud_tags', toUInt64("+podNSIDSuffix+"),'{}')) ",
				"(("+deviceIDSuffix+"!=0 AND "+deviceTypeIDSuffix+"=1) OR "+podNSIDSuffix+"!=0)",
				"",
				"",
			),
		}
	}

	// os.app
	// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
	for _, suffix := range []string{"", "_0", "_1"} {
		osAPPSuffix := "os_app" + suffix
		processIDSuffix := "gprocess_id" + suffix
		tagResourceMap[osAPPSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.os_app_tag_map, 'value', (toUInt64("+processIDSuffix+"),'%s'))",
				"toUInt64("+processIDSuffix+") IN (SELECT pid FROM flow_tag.os_app_tag_map WHERE key='%s')",
				"toUInt64("+processIDSuffix+") IN (SELECT pid FROM flow_tag.os_app_tag_map WHERE value %s %s and key='%s')",
				"toUInt64("+processIDSuffix+") IN (SELECT pid FROM flow_tag.os_app_tag_map WHERE %s(value,%s) and key='%s')",
			),
		}
	}
	for _, suffix := range []string{"", "_0", "_1"} {
		osAPPSuffix := "os.app" + suffix
		processIDSuffix := "gprocess_id" + suffix
		tagResourceMap[osAPPSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGetOrDefault(flow_tag.os_app_tags_map, 'os_app_tags', toUInt64("+processIDSuffix+"),'{}')",
				processIDSuffix+"!=0",
				"",
				"",
			),
		}
	}

	// 单个外部字段-ext_metrics
	tagResourceMap["tag."] = map[string]*Tag{
		"default": NewTag(
			"tag_values[indexOf(tag_names,'%s')]",
			"%s != ''",
			"tag_values[indexOf(tag_names,'%s')] %s %v",
			"%s(tag_values[indexOf(tag_names,'%s')],%v)",
		),
	}
	// 单个外部字段-l7_flow_log
	tagResourceMap["attribute."] = map[string]*Tag{
		"default": NewTag(
			"attribute_values[indexOf(attribute_names,'%s')]",
			"%s != ''",
			"attribute_values[indexOf(attribute_names,'%s')] %s %v",
			"%s(attribute_values[indexOf(attribute_names,'%s')],%v)",
		),
	}
	// 外部字段map
	tagResourceMap["tag"] = map[string]*Tag{
		"default": NewTag(
			// TODO: We can use MAP_FROM_ARRAYS after upgrade ClickHouse,
			// https://clickhouse.com/docs/en/sql-reference/functions/tuple-map-functions/#mapfromarrays
			"toJSONString(CAST((tag_names, tag_values), 'Map(String, String)'))",
			"",
			"",
			"",
		),
	}
	tagResourceMap["attribute"] = map[string]*Tag{
		"default": NewTag(
			"toJSONString(CAST((attribute_names, attribute_values), 'Map(String, String)'))",
			"",
			"",
			"",
		),
	}

	// 外部指标量
	tagResourceMap["metrics."] = map[string]*Tag{
		"default": NewTag(
			"",
			"%s is not null",
			"",
			"",
		),
	}
	tagResourceMap["metrics"] = map[string]*Tag{
		"default": NewTag(
			"toJSONString(CAST((%s, %s), 'Map(String, Float64)'))",
			"",
			"",
			"",
		),
	}
	// 采集点ID
	tagResourceMap["tap_id"] = map[string]*Tag{
		"default": NewTag(
			"capture_network_type_id",
			"",
			"capture_network_type_id %s %s",
			"",
		)}
	// 采集点
	tagResourceMap["tap"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(flow_tag.tap_type_map, 'name', toUInt64(capture_network_type_id))",
			"",
			"toUInt64(capture_network_type_id) IN (SELECT value FROM flow_tag.tap_type_map WHERE name %s %s)",
			"toUInt64(capture_network_type_id) IN (SELECT value FROM flow_tag.tap_type_map WHERE %s(name,%s))",
		)}

	// 采集网络类型
	tagResourceMap["capture_network_type"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(flow_tag.tap_type_map, 'name', toUInt64(capture_network_type_id))",
			"",
			"toUInt64(capture_network_type_id) IN (SELECT value FROM flow_tag.tap_type_map WHERE name %s %s)",
			"toUInt64(capture_network_type_id) IN (SELECT value FROM flow_tag.tap_type_map WHERE %s(name,%s))",
		)}

	// 响应码
	tagResourceMap["response_code"] = map[string]*Tag{
		"default": NewTag(
			"",
			"isNotNull(response_code)",
			"",
			"",
		)}
	// IP类型
	tagResourceMap["ip_version"] = map[string]*Tag{
		"default": NewTag(
			"if(is_ipv4=1, 4, 6)",
			"",
			"is_ipv4 %s %s",
			"",
		)}
	// _ID
	tagResourceMap["_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"_id %s %s AND time=toDateTime(bitShiftRight(%v, 32))",
			"",
		)}
	// tap_port
	tagResourceMap["tap_port"] = map[string]*Tag{
		"default": NewTag(
			"capture_nic",
			"",
			"",
			"",
		)}
	// 采集位置名称
	tagResourceMap["tap_port_name"] = map[string]*Tag{
		"default": NewTag(
			"if(capture_nic_type in (0,1,2),dictGet(flow_tag.vtap_port_map, 'name', (toUInt64(agent_id),toUInt64(capture_nic))),'')",
			"",
			"(toUInt64(agent_id), toUInt64(capture_nic)) IN (SELECT vtap_id, tap_port FROM flow_tag.vtap_port_map WHERE name %s %s)",
			"(toUInt64(agent_id), toUInt64(capture_nic)) IN (SELECT vtap_id, tap_port FROM flow_tag.vtap_port_map WHERE %s(name,%s))",
		)}
	// 采集网卡名称
	tagResourceMap["capture_nic_name"] = map[string]*Tag{
		"default": NewTag(
			"if(capture_nic_type in (0,1,2),dictGet(flow_tag.vtap_port_map, 'name', (toUInt64(agent_id),toUInt64(capture_nic))),'')",
			"",
			"(toUInt64(agent_id), toUInt64(capture_nic)) IN (SELECT vtap_id, tap_port FROM flow_tag.vtap_port_map WHERE name %s %s)",
			"(toUInt64(agent_id), toUInt64(capture_nic)) IN (SELECT vtap_id, tap_port FROM flow_tag.vtap_port_map WHERE %s(name,%s))",
		)}
	// Nat Real IP
	for _, suffix := range []string{"", "_0", "_1"} {
		NatRealIPSuffix := "nat_real_ip" + suffix
		NatRealIP4Suffix := "nat_real_ip4" + suffix
		tagResourceMap[NatRealIPSuffix] = map[string]*Tag{
			"default": NewTag(
				"IPv4NumToString("+NatRealIP4Suffix+")",
				"",
				"hex("+NatRealIP4Suffix+") %s %s",
				"",
			)}
	}
	// Tunnel IP
	tagResourceMap["tunnel_tx_ip_0"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_is_ipv4, IPv4NumToString(tunnel_tx_ip4_0), IPv6NumToString(tunnel_tx_ip6_0))",
			"",
			"if(tunnel_is_ipv4=1, hex(tunnel_tx_ip4_0), hex(tunnel_tx_ip6_0)) %s %s",
			"",
		)}
	tagResourceMap["tunnel_tx_ip_1"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_is_ipv4, IPv4NumToString(tunnel_tx_ip4_1), IPv6NumToString(tunnel_tx_ip6_1))",
			"",
			"if(tunnel_is_ipv4=1, hex(tunnel_tx_ip4_1), hex(tunnel_tx_ip6_1)) %s %s",
			"",
		)}
	tagResourceMap["tunnel_rx_ip_0"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_is_ipv4, IPv4NumToString(tunnel_rx_ip4_0), IPv6NumToString(tunnel_rx_ip6_0))",
			"",
			"if(tunnel_is_ipv4=1, hex(tunnel_rx_ip4_0), hex(tunnel_rx_ip6_0)) %s %s",
			"",
		)}
	tagResourceMap["tunnel_rx_ip_1"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_is_ipv4, IPv4NumToString(tunnel_rx_ip4_1), IPv6NumToString(tunnel_rx_ip6_1))",
			"",
			"if(tunnel_is_ipv4=1, hex(tunnel_rx_ip4_1), hex(tunnel_rx_ip6_1)) %s %s",
			"",
		)}
	// 开始时间
	tagResourceMap["start_time"] = map[string]*Tag{
		"toString": NewTag(
			"toString(start_time)",
			"",
			"",
			"",
		)}
	// 结束时间
	tagResourceMap["end_time"] = map[string]*Tag{
		"toString": NewTag(
			"toString(end_time)",
			"",
			"",
			"",
		)}
	// pod_group_type
	for _, suffix := range []string{"", "_0", "_1"} {
		podGroupIDSuffix := "pod_group_id" + suffix
		podGroupTypeSuffix := "pod_group_type" + suffix
		tagResourceMap[podGroupTypeSuffix] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64("+podGroupIDSuffix+")))",
				podGroupIDSuffix+"!=0",
				"toUInt64("+podGroupIDSuffix+") IN (SELECT id FROM flow_tag.pod_group_map WHERE pod_group_type %s %s) AND "+podGroupIDSuffix+"!=0",
				"",
			),
			"enum": NewTag(
				"dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64(dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64("+podGroupIDSuffix+"))))), dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64("+podGroupIDSuffix+"))))",
				"",
				"toUInt64(dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64("+podGroupIDSuffix+")))) IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s') AND "+podGroupIDSuffix+"!=0",
				"toUInt64(dictGet(flow_tag.pod_group_map, 'pod_group_type', (toUInt64("+podGroupIDSuffix+")))) IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s') AND "+podGroupIDSuffix+"!=0",
			),
		}
	}
	// enum_tag
	for _, enumName := range INT_ENUM_TAG {
		tagResourceMap[enumName] = map[string]*Tag{
			"enum": NewTag(
				"dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64("+enumName+")), "+enumName+")",
				"",
				"toUInt64("+enumName+") IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s')",
				"toUInt64("+enumName+") IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s')",
			),
		}
	}
	for _, enumName := range INT_ENUM_PEER_TAG {
		for _, suffix := range []string{"", "_0", "_1"} {
			tagEnumNameSuffix := enumName + suffix
			enumNameSuffix := enumName + suffix
			if common.IsValueInSliceString(enumName, []string{"resource_gl0_type", "auto_instance_type"}) {
				enumNameSuffix = "auto_instance_type" + suffix
			} else if common.IsValueInSliceString(enumName, []string{"resource_gl1_type", "resource_gl2_type", "auto_service_type"}) {
				enumNameSuffix = "auto_service_type" + suffix
			}
			_, ok := tagResourceMap[tagEnumNameSuffix]
			if ok {
				tagResourceMap[tagEnumNameSuffix]["enum"] = NewTag(
					"dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64("+enumNameSuffix+")), "+enumNameSuffix+")",
					"",
					"toUInt64("+enumNameSuffix+") IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s')",
					"toUInt64("+enumNameSuffix+") IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s')",
				)
			} else {
				tagResourceMap[tagEnumNameSuffix] = map[string]*Tag{
					"enum": NewTag(
						"dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64("+enumNameSuffix+")), "+enumNameSuffix+")",
						"",
						"toUInt64("+enumNameSuffix+") IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s')",
						"toUInt64("+enumNameSuffix+") IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s')",
					),
				}
			}
		}
	}
	// span_kind
	// nullable int_enum tag do not return default value
	tagResourceMap["span_kind"] = map[string]*Tag{
		"enum": NewTag(
			"if(isNull(span_kind), '', dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64(span_kind)), span_kind))",
			"",
			"toUInt64(span_kind) IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s')",
			"toUInt64(span_kind) IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s')",
		)}
	for _, enumName := range STRING_ENUM_TAG {
		tagResourceMap[enumName] = map[string]*Tag{
			"enum": NewTag(
				"dictGetOrDefault(flow_tag.string_enum_map, 'name', ('%s',"+enumName+"), "+enumName+")",
				"",
				enumName+" IN (SELECT value FROM flow_tag.string_enum_map WHERE name %s %s and tag_name='%s')",
				enumName+" IN (SELECT value FROM flow_tag.string_enum_map WHERE %s(name,%s) and tag_name='%s')",
			),
		}
	}
	// tap_side & Enum(tap_side)
	tagResourceMap["tap_side"] = map[string]*Tag{
		"enum": NewTag(
			"dictGetOrDefault(flow_tag.string_enum_map, 'name', ('%s',observation_point), observation_point)",
			"",
			"observation_point IN (SELECT value FROM flow_tag.string_enum_map WHERE name %s %s and tag_name='%s')",
			"observation_point IN (SELECT value FROM flow_tag.string_enum_map WHERE %s(name,%s) and tag_name='%s')",
		),
		"default": NewTag(
			"observation_point",
			"",
			"observation_point %s %s",
			"%s (observation_point, %s)",
		),
	}
	// tap_port_type & Enum(tap_port_type)
	tagResourceMap["tap_port_type"] = map[string]*Tag{
		"enum": NewTag(
			"dictGetOrDefault(flow_tag.int_enum_map, 'name', ('%s',toUInt64(capture_nic_type)), capture_nic_type)",
			"",
			"toUInt64(capture_nic_type) IN (SELECT value FROM flow_tag.int_enum_map WHERE name %s %s and tag_name='%s')",
			"toUInt64(capture_nic_type) IN (SELECT value FROM flow_tag.int_enum_map WHERE %s(name,%s) and tag_name='%s')",
		),
		"default": NewTag(
			"capture_nic_type",
			"",
			"capture_nic_type %s %s",
			"%s(capture_nic_type,%s)",
		),
	}
	// Pcap
	tagResourceMap["has_pcap"] = map[string]*Tag{
		"default": NewTag(
			"notEmpty(acl_gids)",
			"",
			"notEmpty(acl_gids) %s %s",
			"",
		)}
	tagResourceMap["acl_gids"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"has(acl_gids, %s)",
			"",
		)}

	tagResourceMap["packet_batch"] = map[string]*Tag{
		"default": NewTag(
			"TO_BASE64(packet_batch)",
			"",
			"",
			"",
		)}
	// TAP Port Resource
	for tapPortResource, deviceTypeValue := range TAP_PORT_DEVICE_MAP {
		tapPortResourceID := tapPortResource + "_id"
		deviceTypeValueStr := strconv.Itoa(deviceTypeValue)
		tagResourceMap[tapPortResource] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.vtap_port_map, 'device_name', (toUInt64(agent_id),toUInt64(capture_nic)))",
				"(toUInt64(agent_id),toUInt64(capture_nic)) IN (SELECT vtap_id,tap_port FROM flow_tag.vtap_port_map WHERE tap_port!=0 AND device_type="+deviceTypeValueStr+")",
				"(toUInt64(agent_id),toUInt64(capture_nic)) IN (SELECT vtap_id,tap_port FROM flow_tag.vtap_port_map WHERE tap_port!=0 AND device_type="+deviceTypeValueStr+" AND device_name %s %s)",
				"(toUInt64(agent_id),toUInt64(capture_nic)) IN (SELECT vtap_id,tap_port FROM flow_tag.vtap_port_map WHERE tap_port!=0 AND device_type="+deviceTypeValueStr+" AND %s(device_name,%s))",
			)}
		tagResourceMap[tapPortResourceID] = map[string]*Tag{
			"default": NewTag(
				"dictGet(flow_tag.vtap_port_map, 'device_id', (toUInt64(agent_id),toUInt64(capture_nic)))",
				"(toUInt64(agent_id),toUInt64(capture_nic)) IN (SELECT vtap_id,tap_port FROM flow_tag.vtap_port_map WHERE tap_port!=0 AND device_type="+deviceTypeValueStr+")",
				"(toUInt64(agent_id),toUInt64(capture_nic)) IN (SELECT vtap_id,tap_port FROM flow_tag.vtap_port_map WHERE tap_port!=0 AND device_type="+deviceTypeValueStr+" AND device_id %s %s)",
				"",
			)}
	}
	// Policy
	tagResourceMap["policy_id"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_ip_id=0,dictGet(flow_tag.policy_map, 'id', (toUInt64(0),toUInt64(acl_gid))),dictGet(flow_tag.policy_map, 'id', (toUInt64(1),toUInt64(acl_gid))))",
			"",
			"if(tunnel_ip_id=0,dictGet(flow_tag.policy_map, 'id', (toUInt64(0),toUInt64(acl_gid))),dictGet(flow_tag.policy_map, 'id', (toUInt64(1),toUInt64(acl_gid)))) %s %s",
			"",
		),
	}
	tagResourceMap["policy"] = map[string]*Tag{
		"default": NewTag(
			"if(tunnel_ip_id=0,dictGet(flow_tag.policy_map, 'name', (toUInt64(0),toUInt64(acl_gid))),dictGet(flow_tag.policy_map, 'name', (toUInt64(1),toUInt64(acl_gid))))",
			"",
			"(if(tunnel_ip_id=0,toUInt64(0),toUInt64(1)),toUInt64(acl_gid)) IN (SELECT tunnel_type,acl_gid FROM flow_tag.policy_map WHERE name %s %s)",
			"(if(tunnel_ip_id=0,toUInt64(0),toUInt64(1)),toUInt64(acl_gid)) IN (SELECT tunnel_type,acl_gid FROM flow_tag.policy_map WHERE %s(name,%s))",
		),
	}
	// Npb Tunnel
	tagResourceMap["npb_tunnel_id"] = map[string]*Tag{
		"default": NewTag(
			"tunnel_ip_id",
			"",
			"tunnel_ip_id %s %s",
			"",
		),
	}
	tagResourceMap["npb_tunnel"] = map[string]*Tag{
		"default": NewTag(
			"dictGet(flow_tag.npb_tunnel_map, 'name', toUInt64(tunnel_ip_id))",
			"",
			"toUInt64(tunnel_ip_id) IN (SELECT id FROM flow_tag.npb_tunnel_map WHERE name %s %s)",
			"toUInt64(tunnel_ip_id) IN (SELECT id FROM flow_tag.npb_tunnel_map WHERE %s(name,%s))",
		),
	}

	for _, suffix := range []string{"", "_0", "_1"} {
		for resource, fieldInfo := range HOSTNAME_IP_DEVICE_MAP {
			deviceTypeValue := fieldInfo.ResourceType
			deviceTypeValueStr := strconv.Itoa(deviceTypeValue)

			fieldName := fieldInfo.FieldName
			resourceStr := fieldInfo.ResourceName

			resourceIDSuffix := resource + "_id" + suffix
			resourceSuffix := resource + suffix
			if deviceTypeValue == VIF_DEVICE_TYPE_VM {
				deviceTypeSuffix := "l3_device_type" + suffix
				idNameSuffix := "l3_device_id" + suffix
				tagResourceMap[resourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						"if("+deviceTypeSuffix+"="+deviceTypeValueStr+","+idNameSuffix+", 0)",
						idNameSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
						idNameSuffix+" %s %s AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
						"",
					)}
				tagResourceMap[resourceSuffix] = map[string]*Tag{
					"default": NewTag(
						"if("+deviceTypeSuffix+"="+deviceTypeValueStr+", "+
							"dictGet(flow_tag.device_map, '"+fieldName+"', "+
							"(toUInt64("+deviceTypeValueStr+"),toUInt64("+idNameSuffix+"))), '')",
						idNameSuffix+"!=0 AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
						"toUInt64("+idNameSuffix+") IN (SELECT deviceid FROM flow_tag.device_map "+
							"WHERE "+fieldName+" %s %s AND devicetype="+deviceTypeValueStr+") "+
							"AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
						"toUInt64("+idNameSuffix+") IN (SELECT deviceid FROM flow_tag.device_map "+
							"WHERE %s("+fieldName+",%s) AND devicetype="+deviceTypeValueStr+") "+
							"AND "+deviceTypeSuffix+"="+deviceTypeValueStr,
					),
					"node_type": NewTag(
						"'"+resourceStr+"'",
						"",
						"",
						"",
					),
					"icon_id": NewTag(
						"if("+deviceTypeSuffix+"="+deviceTypeValueStr+", dictGet(flow_tag.device_map, 'icon_id', (toUInt64("+deviceTypeValueStr+"),toUInt64("+idNameSuffix+"))), 0)",
						"",
						"",
						"",
					)}
			} else {
				idNameSuffix := fieldInfo.ResourceName + "_id" + suffix
				var iconIdTrans string
				if deviceTypeValue == VIF_DEVICE_TYPE_HOST {
					iconIdTrans = "dictGet(flow_tag.device_map, 'icon_id', (toUInt64(" + deviceTypeValueStr + "),toUInt64(" + idNameSuffix + ")))"
				} else {
					iconIdTrans = "dictGet(flow_tag." + resourceStr + "_map, 'icon_id', (toUInt64(" + idNameSuffix + ")))"
				}

				tagResourceMap[resourceIDSuffix] = map[string]*Tag{
					"default": NewTag(
						idNameSuffix,
						idNameSuffix+"!=0",
						idNameSuffix+" %s %s",
						"",
					)}
				tagResourceMap[resourceSuffix] = map[string]*Tag{
					"default": NewTag(
						"dictGet(flow_tag.device_map, '"+fieldName+"', (toUInt64("+deviceTypeValueStr+"),toUInt64("+idNameSuffix+")))",
						idNameSuffix+"!=0",
						"toUInt64("+idNameSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE "+fieldName+" %s %s AND devicetype="+deviceTypeValueStr+")",
						"toUInt64("+idNameSuffix+") IN (SELECT deviceid FROM flow_tag.device_map WHERE %s("+fieldName+",%s) AND devicetype="+deviceTypeValueStr+")",
					),
					"node_type": NewTag(
						"'"+resourceStr+"'",
						"",
						"",
						"",
					),
					"icon_id": NewTag(iconIdTrans, "", "", "")}
			}
		}
	}
	return tagResourceMap
}

func GenerateFlowTagTagResoureMap() map[string]map[string]*Tag {
	tagResourceMap := make(map[string]map[string]*Tag)

	tagResourceMap["value"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"value %s %s",
			"%s(value, %s)",
		),
	}
	tagResourceMap["display_name"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"display_name %s %s",
			"%s (display_name,%s)",
		),
	}

	tagResourceMap["other_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"%s %s %s",
			"%s (%s, %s)",
		),
	}

	tagResourceMap["ip_resource_name"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"%s_name %s %s",
			"%s (%s_name, %s)",
		),
	}
	tagResourceMap["other_name"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"toUInt64(%s_id) IN (SELECT id FROM flow_tag.%s WHERE name %s %s)",
			"toUInt64(%s_id) IN (SELECT id FROM flow_tag.%s WHERE %s(name,%s))",
		),
	}
	tagResourceMap["device_name"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"toUInt64(%s_id) IN (SELECT deviceid FROM flow_tag.device_map WHERE name %s %s AND devicetype=%d)",
			"toUInt64(%s_id) IN (SELECT deviceid FROM flow_tag.device_map WHERE %s(name,%s) AND devicetype=%d )",
		),
	}

	//enum
	tagResourceMap["enum_tag_id"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"value %s %s",
			"%s (value, %s)",
		),
	}

	tagResourceMap["enum_tag_name"] = map[string]*Tag{
		"default": NewTag(
			"",
			"",
			"name %s %s",
			"%s (name, %s)",
		),
		"enum": NewTag(
			"",
			"",
			"name %s %s",
			"%s (name, %s)",
		),
	}

	return tagResourceMap
}
