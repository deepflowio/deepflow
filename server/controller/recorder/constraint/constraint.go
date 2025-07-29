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

// recorder包中使用到的泛型约束
package constraint

import (
	"time"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type MetadbModelPtr[T MetadbModel] interface {
	*T

	GetLcuuid() string
	GetID() int

	SetID(int)
	SetUpdatedAt(time.Time)
	GetUpdatedAt() time.Time
}

// 资源的 Metadb orm对象
type MetadbModel interface {
	metadbmodel.Region | metadbmodel.AZ | metadbmodel.SubDomain | metadbmodel.Host | metadbmodel.VM |
		metadbmodel.VPC | metadbmodel.Network | metadbmodel.Subnet | metadbmodel.VRouter | metadbmodel.RoutingTable |
		metadbmodel.DHCPPort | metadbmodel.VInterface | metadbmodel.WANIP | metadbmodel.LANIP | metadbmodel.FloatingIP |
		metadbmodel.NATGateway | metadbmodel.NATRule | metadbmodel.NATVMConnection | metadbmodel.LB |
		metadbmodel.LBListener | metadbmodel.LBTargetServer | metadbmodel.LBVMConnection | metadbmodel.CEN |
		metadbmodel.PeerConnection | metadbmodel.RDSInstance | metadbmodel.RedisInstance | metadbmodel.PodCluster |
		metadbmodel.PodNode | metadbmodel.VMPodNodeConnection | metadbmodel.PodNamespace | metadbmodel.PodIngress |
		metadbmodel.PodIngressRule | metadbmodel.PodIngressRuleBackend | metadbmodel.PodService |
		metadbmodel.PodServicePort | metadbmodel.PodGroup | metadbmodel.ConfigMap | metadbmodel.PodGroupConfigMapConnection |
		metadbmodel.PodGroupPort | metadbmodel.PodReplicaSet | metadbmodel.Pod | metadbmodel.Process | metadbmodel.VIP | metadbmodel.CustomService

	GetID() int
	GetUpdatedAt() time.Time
}

// 资源的原始数据结构
type CloudModel interface {
	cloudmodel.Region | cloudmodel.AZ | cloudmodel.SubDomain | cloudmodel.Host | cloudmodel.VM |
		cloudmodel.VPC | cloudmodel.Network | cloudmodel.Subnet | cloudmodel.VRouter | cloudmodel.RoutingTable |
		cloudmodel.DHCPPort | cloudmodel.VInterface | cloudmodel.IP | cloudmodel.FloatingIP |
		cloudmodel.NATGateway | cloudmodel.NATRule | cloudmodel.NATVMConnection | cloudmodel.LB |
		cloudmodel.LBListener | cloudmodel.LBTargetServer | cloudmodel.LBVMConnection | cloudmodel.CEN |
		cloudmodel.PeerConnection | cloudmodel.RDSInstance | cloudmodel.RedisInstance | cloudmodel.PodCluster |
		cloudmodel.PodNode | cloudmodel.VMPodNodeConnection | cloudmodel.PodNamespace | cloudmodel.PodIngress |
		cloudmodel.PodIngressRule | cloudmodel.PodIngressRuleBackend | cloudmodel.PodService |
		cloudmodel.PodServicePort | cloudmodel.PodGroup | cloudmodel.ConfigMap | cloudmodel.PodGroupConfigMapConnection |
		cloudmodel.PodGroupPort | cloudmodel.PodReplicaSet | cloudmodel.Pod | cloudmodel.Process | cloudmodel.VIP
}

// 资源用于比对的缓存对象
type DiffBase interface {
	*diffbase.Region | *diffbase.AZ | *diffbase.SubDomain | *diffbase.Host | *diffbase.VM |
		*diffbase.VPC | *diffbase.Network | *diffbase.Subnet | *diffbase.VRouter | *diffbase.RoutingTable |
		*diffbase.DHCPPort | *diffbase.VInterface | *diffbase.WANIP | *diffbase.LANIP | *diffbase.FloatingIP |
		*diffbase.NATGateway | *diffbase.NATRule | *diffbase.NATVMConnection | *diffbase.LB |
		*diffbase.LBListener | *diffbase.LBTargetServer | *diffbase.LBVMConnection | *diffbase.CEN |
		*diffbase.PeerConnection | *diffbase.RDSInstance | *diffbase.RedisInstance | *diffbase.PodCluster |
		*diffbase.PodNode | *diffbase.VMPodNodeConnection | *diffbase.PodNamespace | *diffbase.PodIngress |
		*diffbase.PodIngressRule | *diffbase.PodIngressRuleBackend | *diffbase.PodService |
		*diffbase.PodServicePort | *diffbase.PodGroup | *diffbase.ConfigMap | *diffbase.PodGroupConfigMapConnection |
		*diffbase.PodGroupPort | *diffbase.PodReplicaSet | *diffbase.Pod | *diffbase.Process | *diffbase.VIP

	GetSequence() int
	SetSequence(sequence int)
	GetLcuuid() string
}

// 软删除资源的 Metadb orm对象
type MetadbSoftDeleteModel interface {
	metadbmodel.Region | metadbmodel.AZ | metadbmodel.Host | metadbmodel.VM | metadbmodel.VPC | metadbmodel.Network |
		metadbmodel.VRouter | metadbmodel.DHCPPort | metadbmodel.NATGateway |
		metadbmodel.LB | metadbmodel.LBListener | metadbmodel.CEN | metadbmodel.PeerConnection | metadbmodel.RDSInstance |
		metadbmodel.RedisInstance | metadbmodel.PodCluster | metadbmodel.PodNode | metadbmodel.PodNamespace |
		metadbmodel.PodIngress | metadbmodel.PodService | metadbmodel.PodGroup | metadbmodel.ConfigMap |
		metadbmodel.PodReplicaSet | metadbmodel.Pod | metadbmodel.Process

	GetDomainLcuuid() string
	GetSubDomainLcuuid() string
}
