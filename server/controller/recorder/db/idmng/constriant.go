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

import "github.com/deepflowio/deepflow/server/controller/db/mysql"

// 资源的MySQL orm对象
type MySQLModel interface {
	mysql.Region | mysql.AZ | mysql.SubDomain | mysql.Host | mysql.VM |
		mysql.VPC | mysql.Network | mysql.VRouter |
		mysql.DHCPPort |
		mysql.NATGateway | mysql.LB |
		mysql.CEN |
		mysql.PeerConnection | mysql.RDSInstance | mysql.RedisInstance | mysql.PodCluster |
		mysql.PodNode | mysql.VMPodNodeConnection | mysql.PodNamespace | mysql.PodIngress |
		mysql.PodService |
		mysql.PodGroup | mysql.PodReplicaSet |
		mysql.Pod | mysql.Process | mysql.VTap

	GetID() int
}
