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

package datatype

import (
	"net"
	"time"
)

const (
	MIN_MASK_LEN      = 0
	STANDARD_MASK_LEN = 16
	MAX_MASK_LEN      = 32
	MAX_MASK6_LEN     = 128
	MASK_LEN_NUM      = MAX_MASK_LEN + 1

	IF_TYPE_WAN = 3

	DATA_VALID_TIME = 1 * time.Minute
	ARP_VALID_TIME  = 1 * time.Minute
)

type IpNet struct {
	RawIp    net.IP
	Netmask  uint32
	SubnetId uint32
}

type PlatformData struct {
	Mac            uint64
	Ips            []IpNet
	EpcId          int32
	Id             uint32
	RegionId       uint32
	PodClusterId   uint32
	PodNodeId      uint32
	IfType         uint8
	DeviceType     uint8
	IsVIPInterface bool
	// 适配windows hyper-v场景出现的在不同Region存在相同MAC，PlatformData查询GRPC下发的Region id,
	// PlatformData不在同一Region中，该字段为True, 若为true不会创建mac表
	SkipMac bool
	// 适配青云场景，同子网跨宿主机时采集中间网卡流量，流量MAC地址均为虚拟机MAC（可以打上L3end），但是无法打上L2end为了区分需要
	// 链路追踪具体统计哪一端，引入该字段
	IsLocal bool // 平台数据为当前宿主机的虚拟机（local segment）设置为true
}
