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

package model

type RefreshCacheParam struct {
	RefreshCache bool `schema:"refresh_cache,omitempty"`
}

type IncludedFieldsParam struct {
	IncludedFields []string `schema:"field,omitempty"`
}

func (i IncludedFieldsParam) GetIncludedFields() []string {
	return i.IncludedFields
}

// VMQuery defines supported field in query string, and uses tag (schema) to define the parameter name
// 定义可支持 query 字段，使用 tag（schema）定义参数名
type VMQuery struct {
	VMQueryStoredInRedis
	RefreshCacheParam
}

// VMQueryStoredInRedis defines the fields that need to be used to build the redis cache key
// 定义需用于构建 redis 缓存 key 的字段
type VMQueryStoredInRedis struct {
	VMQueryFilterConditions
	IncludedFieldsParam
}

type HostQuery struct {
	HostQueryStoredInRedis
	RefreshCacheParam
}

type HostQueryStoredInRedis struct {
	HostQueryFilterConditions
	IncludedFieldsParam
}

type IPQuery struct {
	IPQueryStoredInRedis
	RefreshCacheParam
}

type IPQueryStoredInRedis struct {
	IPQueryFilterConditions
	IncludedFieldsParam
}

type DHCPPortQuery struct {
	DHCPPortQueryStoredInRedis
	RefreshCacheParam
}

type DHCPPortQueryStoredInRedis struct {
	DHCPPortQueryFilterConditions
	IncludedFieldsParam
}

type VRouterQuery struct {
	VRouterQueryStoredInRedis
	RefreshCacheParam
}

type VRouterQueryStoredInRedis struct {
	VRouterQueryFilterConditions
	IncludedFieldsParam
}

type RoutingTableQuery struct {
	RoutingTableQueryStoredInRedis
	RefreshCacheParam
}

type RoutingTableQueryStoredInRedis struct {
	RoutingTableQueryFilterConditions
}

type NetworkQuery struct {
	NetworkQueryStoredInRedis
	RefreshCacheParam
}

type NetworkQueryStoredInRedis struct {
	NetworkQueryFilterConditions
	IncludedFieldsParam
}

type VPCQuery struct {
	VPCQueryStoredInRedis
	RefreshCacheParam
}

type VPCQueryStoredInRedis struct {
	VPCQueryFilterConditions
	IncludedFieldsParam
}

type PodQuery struct {
	PodQueryStoredInRedis
	RefreshCacheParam
}

type PodQueryStoredInRedis struct {
	PodQueryFilterConditions
	IncludedFieldsParam
}

type PodReplicaSetQuery struct {
	PodReplicaSetQueryStoredInRedis
	RefreshCacheParam
}

type PodReplicaSetQueryStoredInRedis struct {
	PodReplicaSetQueryFilterConditions
	IncludedFieldsParam
}

type PodGroupQuery struct {
	PodGroupQueryStoredInRedis
	RefreshCacheParam
}

type PodGroupQueryStoredInRedis struct {
	PodGroupQueryFilterConditions
	IncludedFieldsParam
}

type PodGroupPortQuery struct {
	PodGroupPortQueryStoredInRedis
	RefreshCacheParam
}

type PodGroupPortQueryStoredInRedis struct {
	PodGroupPortQueryFilterConditions
	IncludedFieldsParam
}

type PodServiceQuery struct {
	PodServiceQueryStoredInRedis
	RefreshCacheParam
}

type PodServiceQueryStoredInRedis struct {
	PodServiceQueryFilterConditions
	IncludedFieldsParam
}

type PodServicePortQuery struct {
	PodServicePortQueryStoredInRedis
	RefreshCacheParam
}

type PodServicePortQueryStoredInRedis struct {
	PodServicePortQueryFilterConditions
	IncludedFieldsParam
}

type PodIngressQuery struct {
	PodIngressQueryStoredInRedis
	RefreshCacheParam
}

type PodIngressQueryStoredInRedis struct {
	PodIngressQueryFilterConditions
	IncludedFieldsParam
}

type PodIngressRuleQuery struct {
	PodIngressRuleQueryStoredInRedis
	RefreshCacheParam
}

type PodIngressRuleQueryStoredInRedis struct {
	PodIngressRuleQueryFilterConditions
	IncludedFieldsParam
}

type PodNodeQuery struct {
	PodNodeQueryStoredInRedis
	RefreshCacheParam
}

type PodNodeQueryStoredInRedis struct {
	PodNodeQueryFilterConditions
	IncludedFieldsParam
}

type PodNamespaceQuery struct {
	PodNamespaceQueryStoredInRedis
	RefreshCacheParam
}

type PodNamespaceQueryStoredInRedis struct {
	PodNamespaceQueryFilterConditions
	IncludedFieldsParam
}

type PodClusterQuery struct {
	PodClusterQueryStoredInRedis
	RefreshCacheParam
}

type PodClusterQueryStoredInRedis struct {
	PodClusterQueryFilterConditions
	IncludedFieldsParam
}
