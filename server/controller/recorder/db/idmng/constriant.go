/**
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

package idmng

import (
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// 资源的MySQL orm对象
type MySQLModel interface {
	mysqlmodel.Region | mysqlmodel.AZ | mysqlmodel.SubDomain | mysqlmodel.Host | mysqlmodel.VM |
		mysqlmodel.VPC | mysqlmodel.Network | mysqlmodel.VRouter |
		mysqlmodel.DHCPPort |
		mysqlmodel.NATGateway | mysqlmodel.LB |
		mysqlmodel.CEN |
		mysqlmodel.PeerConnection | mysqlmodel.RDSInstance | mysqlmodel.RedisInstance | mysqlmodel.PodCluster |
		mysqlmodel.PodNode | mysqlmodel.VMPodNodeConnection | mysqlmodel.PodNamespace | mysqlmodel.PodIngress |
		mysqlmodel.PodService |
		mysqlmodel.PodGroup | mysqlmodel.PodReplicaSet |
		mysqlmodel.Pod | mysqlmodel.Process | mysqlmodel.VTap | mysqlmodel.ORG

	GetID() int
}
