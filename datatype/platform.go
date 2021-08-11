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
	// 当kvm内的虚拟机为k8s node时，不采集该虚拟的流量，虚拟机流量由k8s node内的trident采集
	// 目前通过pod_node_id>0 && pod_cluster_id>0判定
	SkipTapInterface bool
	// 适配青云场景，同子网跨宿主机时采集中间网卡流量，流量MAC地址均为虚拟机MAC（可以打上L3end），但是无法打上L2end为了区分需要
	// 链路追踪具体统计哪一端，引入该字段
	IsLocal bool // 平台数据为当前宿主机的虚拟机（local segment）设置为true
}
