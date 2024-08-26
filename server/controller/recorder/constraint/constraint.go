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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type MySQLModelPtr[T MySQLModel] interface {
	*T

	GetLcuuid() string
	GetID() int

	SetID(int)
	SetUpdatedAt(time.Time)
}

// 资源的MySQL orm对象
type MySQLModel interface {
	mysqlmodel.Region | mysqlmodel.AZ | mysqlmodel.SubDomain | mysqlmodel.Host | mysqlmodel.VM |
		mysqlmodel.VPC | mysqlmodel.Network | mysqlmodel.Subnet | mysqlmodel.VRouter | mysqlmodel.RoutingTable |
		mysqlmodel.DHCPPort | mysqlmodel.VInterface | mysqlmodel.WANIP | mysqlmodel.LANIP | mysqlmodel.FloatingIP |
		mysqlmodel.NATGateway | mysqlmodel.NATRule | mysqlmodel.NATVMConnection | mysqlmodel.LB |
		mysqlmodel.LBListener | mysqlmodel.LBTargetServer | mysqlmodel.LBVMConnection | mysqlmodel.CEN |
		mysqlmodel.PeerConnection | mysqlmodel.RDSInstance | mysqlmodel.RedisInstance | mysqlmodel.PodCluster |
		mysqlmodel.PodNode | mysqlmodel.VMPodNodeConnection | mysqlmodel.PodNamespace | mysqlmodel.PodIngress |
		mysqlmodel.PodIngressRule | mysqlmodel.PodIngressRuleBackend | mysqlmodel.PodService |
		mysqlmodel.PodServicePort | mysqlmodel.PodGroup | mysqlmodel.PodGroupPort | mysqlmodel.PodReplicaSet |
		mysqlmodel.Pod | mysqlmodel.Process | mysqlmodel.VIP

	GetID() int
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
		cloudmodel.PodServicePort | cloudmodel.PodGroup | cloudmodel.PodGroupPort | cloudmodel.PodReplicaSet |
		cloudmodel.Pod | cloudmodel.Process | cloudmodel.VIP
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
		*diffbase.PodServicePort | *diffbase.PodGroup | *diffbase.PodGroupPort | *diffbase.PodReplicaSet |
		*diffbase.Pod | *diffbase.Process | *diffbase.VIP

	GetSequence() int
	SetSequence(sequence int)
	GetLcuuid() string
}

// 软删除资源的MySQL orm对象
type MySQLSoftDeleteModel interface {
	mysqlmodel.Region | mysqlmodel.AZ | mysqlmodel.Host | mysqlmodel.VM | mysqlmodel.VPC | mysqlmodel.Network |
		mysqlmodel.VRouter | mysqlmodel.DHCPPort | mysqlmodel.NATGateway |
		mysqlmodel.LB | mysqlmodel.LBListener | mysqlmodel.CEN | mysqlmodel.PeerConnection | mysqlmodel.RDSInstance |
		mysqlmodel.RedisInstance | mysqlmodel.PodCluster | mysqlmodel.PodNode | mysqlmodel.PodNamespace |
		mysqlmodel.PodIngress | mysqlmodel.PodService | mysqlmodel.PodGroup | mysqlmodel.PodReplicaSet | mysqlmodel.Pod |
		mysqlmodel.Process

	GetDomainLcuuid() string
	GetSubDomainLcuuid() string
}
