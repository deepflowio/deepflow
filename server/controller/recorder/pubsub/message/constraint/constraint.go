/**
 * Copyright (c) 2023 Yunshan Networks
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

package constraint

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type AddPtr[T Add] interface {
	*T

	SetMySQLItems(interface{})
	GetMySQLItems() interface{} // return []*constraint.MySQLModel
}

type Add interface {
	message.RegionAdd | message.AZAdd | message.SubDomainAdd | message.HostAdd | message.VMAdd |
		message.VPCAdd | message.NetworkAdd | message.SubnetAdd | message.VRouterAdd | message.RoutingTableAdd |
		message.DHCPPortAdd | message.VInterfaceAdd | message.WANIPAdd | message.LANIPAdd | message.FloatingIPAdd |
		message.SecurityGroupAdd | message.SecurityGroupRuleAdd | message.VMSecurityGroupAdd |
		message.NATGatewayAdd | message.NATRuleAdd | message.NATVMConnectionAdd | message.LBAdd |
		message.LBListenerAdd | message.LBTargetServerAdd | message.LBVMConnectionAdd | message.CENAdd |
		message.PeerConnectionAdd | message.RDSInstanceAdd | message.RedisInstanceAdd | message.PodClusterAdd |
		message.PodNodeAdd | message.VMPodNodeConnectionAdd | message.PodNamespaceAdd | message.PodIngressAdd |
		message.PodIngressRuleAdd | message.PodIngressRuleBackendAdd | message.PodServiceAdd |
		message.PodServicePortAdd | message.PodGroupAdd | message.PodGroupPortAdd | message.PodReplicaSetAdd |
		message.PodAdd | message.ProcessAdd | message.PrometheusTargetAdd | message.VIPAdd
}

type UpdatePtr[T Update] interface {
	*T

	// SetID(int)
	// GetID() int
	// SetLcuuid(string)
	// GetLcuuid() string
	SetFields(interface{})
	GetFields() interface{} // return *FieldsUpdate
	SetDiffBase(interface{})
	GetDiffBase() interface{} // return *constraint.DiffBase
	SetCloudItem(interface{})
	GetCloudItem() interface{} // return *constraint.CloudModel
}

// Update是所有资源更新消息的泛型约束
type Update interface {
	message.RegionUpdate | message.AZUpdate | message.SubDomainUpdate | message.HostUpdate | message.VMUpdate |
		message.VPCUpdate | message.NetworkUpdate | message.SubnetUpdate | message.VRouterUpdate | message.RoutingTableUpdate |
		message.DHCPPortUpdate | message.VInterfaceUpdate | message.WANIPUpdate | message.LANIPUpdate | message.FloatingIPUpdate |
		message.SecurityGroupUpdate | message.SecurityGroupRuleUpdate | message.VMSecurityGroupUpdate |
		message.NATGatewayUpdate | message.NATRuleUpdate | message.NATVMConnectionUpdate | message.LBUpdate |
		message.LBListenerUpdate | message.LBTargetServerUpdate | message.LBVMConnectionUpdate | message.CENUpdate |
		message.PeerConnectionUpdate | message.RDSInstanceUpdate | message.RedisInstanceUpdate | message.PodClusterUpdate |
		message.PodNodeUpdate | message.VMPodNodeConnectionUpdate | message.PodNamespaceUpdate | message.PodIngressUpdate |
		message.PodIngressRuleUpdate | message.PodIngressRuleBackendUpdate | message.PodServiceUpdate |
		message.PodServicePortUpdate | message.PodGroupUpdate | message.PodGroupPortUpdate | message.PodReplicaSetUpdate |
		message.PodUpdate | message.ProcessUpdate | message.PrometheusTargetUpdate | message.VIPUpdate
}

type FieldsUpdatePtr[T FieldsUpdate] interface {
	*T

	SetID(int)
	GetID() int
	SetLcuuid(string)
	GetLcuuid() string
}

type FieldsUpdate interface {
	message.RegionFieldsUpdate | message.AZFieldsUpdate | message.SubDomainFieldsUpdate | message.HostFieldsUpdate |
		message.VMFieldsUpdate | message.VPCFieldsUpdate | message.NetworkFieldsUpdate | message.SubnetFieldsUpdate |
		message.VRouterFieldsUpdate | message.RoutingTableFieldsUpdate | message.DHCPPortFieldsUpdate |
		message.VInterfaceFieldsUpdate | message.WANIPFieldsUpdate | message.LANIPFieldsUpdate | message.FloatingIPFieldsUpdate |
		message.SecurityGroupFieldsUpdate | message.SecurityGroupRuleFieldsUpdate | message.VMSecurityGroupFieldsUpdate |
		message.NATGatewayFieldsUpdate | message.NATRuleFieldsUpdate | message.NATVMConnectionFieldsUpdate | message.LBFieldsUpdate |
		message.LBListenerFieldsUpdate | message.LBTargetServerFieldsUpdate | message.LBVMConnectionFieldsUpdate | message.CENFieldsUpdate |
		message.PeerConnectionFieldsUpdate | message.RDSInstanceFieldsUpdate | message.RedisInstanceFieldsUpdate | message.PodClusterFieldsUpdate |
		message.PodNodeFieldsUpdate | message.VMPodNodeConnectionFieldsUpdate | message.PodNamespaceFieldsUpdate | message.PodIngressFieldsUpdate |
		message.PodIngressRuleFieldsUpdate | message.PodIngressRuleBackendFieldsUpdate | message.PodServiceFieldsUpdate |
		message.PodServicePortFieldsUpdate | message.PodGroupFieldsUpdate | message.PodGroupPortFieldsUpdate | message.PodReplicaSetFieldsUpdate |
		message.PodFieldsUpdate | message.ProcessFieldsUpdate | message.PrometheusTargetFieldsUpdate | message.VIPFieldsUpdate
}

type DeletePtr[T Delete] interface {
	*T

	SetLcuuids([]string)
	GetLcuuids() []string
	SetMySQLItems(interface{})
	GetMySQLItems() interface{} // return []*constraint.MySQLModel
}

type Delete interface {
	message.RegionDelete | message.AZDelete | message.SubDomainDelete | message.HostDelete | message.VMDelete |
		message.VPCDelete | message.NetworkDelete | message.SubnetDelete | message.VRouterDelete | message.RoutingTableDelete |
		message.DHCPPortDelete | message.VInterfaceDelete | message.WANIPDelete | message.LANIPDelete | message.FloatingIPDelete |
		message.SecurityGroupDelete | message.SecurityGroupRuleDelete | message.VMSecurityGroupDelete |
		message.NATGatewayDelete | message.NATRuleDelete | message.NATVMConnectionDelete | message.LBDelete |
		message.LBListenerDelete | message.LBTargetServerDelete | message.LBVMConnectionDelete | message.CENDelete |
		message.PeerConnectionDelete | message.RDSInstanceDelete | message.RedisInstanceDelete | message.PodClusterDelete |
		message.PodNodeDelete | message.VMPodNodeConnectionDelete | message.PodNamespaceDelete | message.PodIngressDelete |
		message.PodIngressRuleDelete | message.PodIngressRuleBackendDelete | message.PodServiceDelete |
		message.PodServicePortDelete | message.PodGroupDelete | message.PodGroupPortDelete | message.PodReplicaSetDelete |
		message.PodDelete | message.ProcessDelete | message.PrometheusTargetDelete | message.VIPDelete
}
