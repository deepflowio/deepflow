/*
 * Copyright (c) 2022 Yunshan Networks
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

package example

var YamlDomainKubernetes = []byte(`
# 名称
name: kubernetes
# 云平台类型
type: kubernetes
config:
  # 所属区域标识
  region_uuid: ffffffff-ffff-ffff-ffff-ffffffffffff
  # 资源同步控制器
  #controller_ip: 127.0.0.1
  # POD子网IPv4地址最大掩码
  pod_net_ipv4_cidr_max_mask: 16
  # POD子网IPv6地址最大掩码
  pod_net_ipv6_cidr_max_mask: 64
  # 额外对接路由接口
  port_name_regex: ^(cni|flannel|cali|vxlan.calico|tunl)
`)
