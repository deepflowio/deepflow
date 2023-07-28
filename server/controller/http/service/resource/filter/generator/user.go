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

//  资源管理实现

//  1. 全部对租户开放的资源

//  * 资源池
//    - 区域
//    - 可用区
//    - 云平台
//  * 网络服务
//    - 安全组
//    - 对等连接
//    - 云企业网

//  1. 全部对租户不开放的资源

//  * 计算资源
//    - 宿主机

//  2. 过滤逻辑

//  综合过滤说明

//  * 最终呈现的数据，`是根据VPC过滤结果与命名空间过滤结果的并集`
//  * 如果按照授权条件过滤后的资源中，有使用到没有授权的某VPC下的共享网络，应将这个VPC进行授权

//  根据VPC授权过滤逻辑

//  * 计算资源
//    - 云服务器：VPC->VPC关联云服务器
//    - 云服务器网卡：VPC->云服务器->网卡
//    - 宿主机，租户无权限
//  * 网络资源
//    - VPC：VPC
//    - 子网：VPC->VPC关联子网
//    - 路由器：VPC->VPC关联路由器
//    - DHCP网关：VPC->VPC关联DHCP网关
//    - IP：VPC->VPC关联各种设备->设备关联IP
//  * 网络服务
//    - NAT网关：VPC->VPC关联NAT网关
//    - 负载均衡器：VPC->VPC关联负载均衡器
//  * 存储服务
//    - RDS：VPC->VPC关联RDS
//    - REDIS：VPC->VPC关联REDIS
//  * 容器
//    - 容器集群：VPC->VPC关联集群
//    - 容器节点：VPC->VPC关联集群->集群关联容器节点
//    - 命名空间：VPC->VPC关联集群->集群关联命名空间
//    - INGRESS：VPC->VPC关联集群->集群关联INGRESS
//    - 服务：VPC->VPC关联服务
//    - 工作负载：VPC->VPC关联集群->集群关联工作负载
//    - ReplicaSet：VPC->VPC关联集群->集群关联ReplicaSet
//    - POD：VPC->VPC关联POD

//  根据命名空间授权过滤逻辑

//  * 计算资源
//    - <mark>云服务器：命名空间->POD->节点->云服务器</mark>
//    - 云服务器网卡：命名空间、VPC->云服务器->网卡
//    - 宿主机，租户无权限
//  * 网络资源
//    - `VPC：命名空间->所属集群->VPC`
//    - `子网：命名空间->所属集群->VPC->VPC关联子网`
//    - 路由器：没有关联，不会获取
//    - DHCP网关：没有关联，不会获取
//    - <mark>IP：命名空间->POD->节点->云服务器->云服务器相关IP</mark>
//  * 网络服务
//    - NAT网关：没有关联，不会获取
//    - 负载均衡器：没有关联，不会获取
//  * 存储服务
//    - RDS：没有关联，不会获取
//    - REDIS：没有关联，不会获取
//  * 容器
//    - 容器集群：命名空间->集群
//    - 容器节点：命名空间->集群->集群关联容器节点
//    - 命名空间：命名空间
//    - INGRESS：命名空间->命名空间关联INGRESS
//    - 服务：命名空间->命名空间关联服务
//    - 工作负载：命名空间->命名空间关联工作负载
//    - ReplicaSet：命名空间->命名空间关联ReplicaSet
//    - POD：命名空间->命名空间关联POD

package generator

import (
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

var FPERMIT_RESOURCE_TYPE_VPC = "vpc"
var FPERMIT_RESOURCE_TYPE_POD_NAMESPACE = "namespace"

type UserPermittedResource struct {
	VPCIDs          []int
	PodNamespaceIDs []int
}

func (u *UserPermittedResource) HasPermittedResource() bool {
	return len(u.VPCIDs) != 0 || len(u.PodNamespaceIDs) != 0
}

func IsAdmin(userType int) bool {
	if slices.Contains([]int{common.USER_TYPE_SUPER_ADMIN, common.USER_TYPE_ADMIN}, userType) {
		return true
	}
	return false
}
