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

var YamlDomainAdditionalResourceReader = []byte(`
domains:
# 云平台唯一标识lcuuid
- lcuuid: xxxx
  # 可用区
  azs:
  # 必填
  - name: xxxx
    # 必填
    lcuuid: xxxx
    # 必填
    region_lcuuid: xxxx
  # VPC
  vpcs:
  # 必填
  - name: xxxx
    # 必填
    lcuuid: xxxx
    # 必填
    region_lcuuid: xxxx
  # 网络
  networks:
  # 必填
  - name: xxxx
    # 必填
    lcuuid: xxxx
    # 网络类型，可选项：3-wan、4-lan，必填
    net_type: 3
    # 默认为false
    is_vip: true/false
    # 必填
    vpc_lcuuid: xxxx
    az_lcuuid: xxxx
    # 必填
    region_lcuuid: xxxx
    # 网段
    subnets:
    # 必填
    - name: xxxx
      # 必填
      lcuuid: xxxx
      # 必填
      cidr: x.x.x.x/xx
      gateway_ip: x.x.x.x
  # 宿主机
  hosts:
  # 必填
  - name: xxxx
    # 必填
    lcuuid: xxxx
    # 必填
    ip: x.x.x.x
    # 类型，可选项：2-ESXi、3-KVM、5-Hyper-V、6-Gateway，默认：3-KVM
    htype: 3
    az_lcuuid: xxxx
    # 必填
    region_lcuuid: xxxx
    # 宿主机的接口
    vinterfaces:
    # 必填
    - mac: xx:xx:xx:xx:xx:xx
      # 接口的IP
      ips:
      # 必填
      - ip: x.x.x.x
        # 必填
        subnet_lcuuid: x.x.x.x
  # 云服务器
  vms:
  # 必填
  - name: xxxx
    # 必填
    lcuuid: xxxx
    # 所属宿主机IP，必填
    launch_server: x.x.x.x
    # 类型，可选项：1-虚拟机/计算、2-裸金属/计算、3-虚拟机/网络、4-裸金属/网络、5-虚拟机/存储、6-裸金属/存储，默认：1-虚拟机/计算
    htype: 1
    # 必填
    vpc_lcuuid: xxxx
    az_lcuuid: xxxx
    # 必填
    region_lcuuid: xxxx
    # 云服务器的接口
    vinterfaces:
    # 必填
    - mac: xx:xx:xx:xx:xx:xx
      # 接口的IP
      ips:
      # 必填
      - ip: x.x.x.x
        # 必填
        subnet_lcuuid: x.x.x.x
`)
