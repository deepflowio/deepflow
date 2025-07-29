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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// 资源的 Metadb orm对象
type MetadbModel interface {
	metadbmodel.Region | metadbmodel.AZ | metadbmodel.SubDomain | metadbmodel.Host | metadbmodel.VM |
		metadbmodel.VPC | metadbmodel.Network | metadbmodel.VRouter |
		metadbmodel.DHCPPort |
		metadbmodel.NATGateway | metadbmodel.LB |
		metadbmodel.CEN |
		metadbmodel.PeerConnection | metadbmodel.RDSInstance | metadbmodel.RedisInstance | metadbmodel.PodCluster |
		metadbmodel.PodNode | metadbmodel.VMPodNodeConnection | metadbmodel.PodNamespace | metadbmodel.PodIngress |
		metadbmodel.PodService |
		metadbmodel.PodGroup | metadbmodel.PodReplicaSet |
		metadbmodel.Pod | metadbmodel.Process | metadbmodel.VTap | metadbmodel.ORG

	GetID() int
}
