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

use std::{
    fmt,
    mem::swap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process,
    time::Duration,
};

use log::{error, warn};

use crate::common::endpoint::EPC_FROM_INTERNET;
use public::proto::{common::TridentType, flow_log};
use public::utils::net::MacAddr;

pub use public::common::enums::{Direction, L4Protocol};
pub use public::common::flow::*;
pub use public::common::l7_protocol::*;

const COUNTER_FLOW_ID_MASK: u64 = 0x00FFFFFF;

pub fn get_direction(
    flow: &Flow,
    trident_type: TridentType,
    cloud_gateway_traffic: bool, // 从static config 获取
) -> (Direction, Direction, bool) {
    // 返回值分别为统计点对应的zerodoc.DirectionEnum以及及是否添加追踪数据的开关，在微软
    // 云MUX场景中，云内和云外通过VIP通信，在MUX和宿主机中采集到的流量IP地址为VIP，添加追
    // 踪数据后会将VIP替换为实际虚拟机的IP。
    fn inner(
        tap_type: TapType,
        tunnel: &TunnelField,
        l2_end: bool,
        l3_end: bool,
        is_vip: bool,
        is_unicast: bool,
        is_local_mac: bool,
        is_local_ip: bool,
        l3_epc_id: i32,
        cloud_gateway_traffic: bool, // 从static config 获取
        trident_type: TridentType,
    ) -> (Direction, Direction, bool) {
        let is_ep = l2_end && l3_end;
        let tunnel_tier = tunnel.tier;
        let mut add_tracing_doc = false;

        match trident_type {
            TridentType::TtDedicatedPhysicalMachine => {
                //  接入网络
                if tap_type != TapType::Cloud {
                    if l3_epc_id != EPC_FROM_INTERNET {
                        return (
                            Direction::ClientToServer,
                            Direction::ServerToClient,
                            add_tracing_doc,
                        );
                    }
                } else {
                    // 虚拟网络
                    // 腾讯TCE场景，NFV区域的镜像流量规律如下（---表示无隧道路径，===表示有隧道路径）：
                    //   WAN ---> NFV1 ===> NFV2 ===> CVM
                    //         ^       ^ ^       ^
                    //         |       | |       `镜像流量有隧道（GRE）、左侧L2End=True
                    //         |       | `镜像流量有隧道（VXLAN/IPIP）、右侧L2End=True
                    //         |       |   <不同类NFV串联时，中间必过路由，MAC会变化>
                    //         |       `镜像流量有隧道（VXLAN/IPIP）、左侧L2End=True
                    //         `镜像流量无隧道、右侧L2End=True
                    //
                    //   CVM ===> NFV1 ===> NFV2 ===> CVM
                    //         ^
                    //         `镜像流量有隧道（GRE）、右侧L2End=True
                    //
                    //   当从WAN访问CVM时，必定有一侧是Internet IP；当云内资源经由NFV互访时，两端都不是Internet IP。
                    //   另外，穿越NFV的过程中内层IP不会变，直到目的端CVM宿主机上才会从GRE Key中提取出RSIP进行替换。
                    //
                    // 腾讯TCE场景下，通过手动录入Type=Gateway类型的宿主机，控制器下发的RemoteSegment等于Gateway的MAC。
                    // 其他场景下不会有此类宿主机，控制器下发的RemoteSegment等于**没有**KVM/K8s等本地采集器覆盖的资源MAC。
                    if l2_end {
                        if cloud_gateway_traffic {
                            // 云网关镜像（腾讯TCE等）
                            // 注意c/s方向与0/1相反
                            return (
                                Direction::ServerGatewayToClient,
                                Direction::ClientGatewayToServer,
                                add_tracing_doc,
                            );
                        } else {
                            return (
                                Direction::ClientToServer,
                                Direction::ServerToClient,
                                add_tracing_doc,
                            );
                        }
                    }
                }
            }
            TridentType::TtHyperVCompute => {
                // 仅采集宿主机物理口
                if l2_end {
                    // SNAT、LB Backend
                    // IP地址为VIP: 将双端(若不是vip_iface)的VIP替换为其MAC对对应的RIP,生成另一份doc
                    add_tracing_doc = is_vip;
                    return (
                        Direction::ClientHypervisorToServer,
                        Direction::ServerHypervisorToClient,
                        add_tracing_doc,
                    );
                }
            }
            TridentType::TtHyperVNetwork => {
                // 仅采集宿主机物理口
                if is_ep {
                    return (
                        Direction::ClientHypervisorToServer,
                        Direction::ServerHypervisorToClient,
                        add_tracing_doc,
                    );
                }

                if l2_end && is_unicast {
                    if !is_vip {
                        // Router
                        // windows hyper-v场景采集到的流量ttl还未减1，这里需要屏蔽ttl避免l3end为true
                        // 注意c/s方向与0/1相反
                        return (
                            Direction::ServerGatewayHypervisorToClient,
                            Direction::ClientGatewayHypervisorToServer,
                            add_tracing_doc,
                        );
                    } else {
                        //MUX
                        add_tracing_doc = tunnel_tier > 0;
                        return (
                            Direction::ServerGatewayHypervisorToClient,
                            Direction::ClientGatewayHypervisorToServer,
                            add_tracing_doc,
                        );
                    }
                }
            }
            TridentType::TtPublicCloud | TridentType::TtPhysicalMachine => {
                // 该采集器类型中统计位置为客户端网关/服务端网关或存在VIP时，需要增加追踪数据
                // VIP：
                //     微软ACS云内SLB通信场景，在VM内采集的流量无隧道IP地址使用VIP,
                //     将对端的VIP替换为其mac对应的RIP，生成另一份doc
                add_tracing_doc = is_vip;
                if is_ep {
                    return (
                        Direction::ClientToServer,
                        Direction::ServerToClient,
                        add_tracing_doc,
                    );
                } else if l2_end {
                    if is_unicast {
                        // 注意c/s方向与0/1相反
                        return (
                            Direction::ServerGatewayToClient,
                            Direction::ClientGatewayToServer,
                            add_tracing_doc,
                        );
                    }
                }
            }
            TridentType::TtHostPod | TridentType::TtVmPod => {
                if is_ep {
                    if tunnel_tier == 0 {
                        return (
                            Direction::ClientToServer,
                            Direction::ServerToClient,
                            add_tracing_doc,
                        );
                    } else {
                        // tunnelTier > 0：容器节点的出口做隧道封装
                        return (
                            Direction::ClientNodeToServer,
                            Direction::ServerNodeToClient,
                            add_tracing_doc,
                        );
                    }
                } else if l2_end {
                    if is_local_ip {
                        // 本机IP：容器节点的出口做路由转发
                        return (
                            Direction::ClientNodeToServer,
                            Direction::ServerNodeToClient,
                            add_tracing_doc,
                        );
                    } else if tunnel_tier > 0 {
                        // tunnelTier > 0：容器节点的出口做隧道封装
                        // 例如：两个容器节点之间打隧道，隧道内层IP为tunl0接口的/32隧道专用IP
                        // 但由于tunl0接口有时候没有MAC，不会被控制器记录，因此不会匹配isLocalIp的条件
                        return (
                            Direction::ClientNodeToServer,
                            Direction::ServerNodeToClient,
                            add_tracing_doc,
                        );
                    }
                    // 其他情况
                    // 举例：在tun0接收到的、本地POD发送到容器节点外部的流量
                    //       其目的MAC为tun0且l2End为真，但目的IP不是本机的IP
                } else if l3_end {
                    if is_local_mac {
                        // 本机MAC：容器节点的出口做交换转发
                        // 平安Serverless容器集群中，容器POD访问的流量特征为：
                        //   POD -> 外部：源MAC=Node MAC（Node路由转发）
                        //   POD <- 外部：目MAC=POD MAC（Node交换转发）
                        return (
                            Direction::ClientNodeToServer,
                            Direction::ServerNodeToClient,
                            add_tracing_doc,
                        );
                    }
                } else {
                    if is_local_mac {
                        if is_local_ip {
                            return (
                                Direction::ClientNodeToServer,
                                Direction::ServerNodeToClient,
                                add_tracing_doc,
                            );
                        } else if tunnel_tier > 0 {
                            return (
                                Direction::ClientNodeToServer,
                                Direction::ServerNodeToClient,
                                add_tracing_doc,
                            );
                        } else {
                            //其他情况: BUM流量
                        }
                    } else {
                        //其他情况: BUM流量
                    }
                }
            }
            TridentType::TtProcess => {
                if is_ep {
                    if tunnel_tier == 0 {
                        return (
                            Direction::ClientToServer,
                            Direction::ServerToClient,
                            add_tracing_doc,
                        );
                    } else {
                        // 宿主机隧道转发
                        if is_local_ip {
                            // 端点VTEP
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                                add_tracing_doc,
                            );
                        }
                        // 其他情况
                        // 中间VTEP：VXLAN网关（二层网关）
                    }
                } else if l2_end {
                    if is_local_ip {
                        if tunnel_tier > 0 {
                            // 容器节点作为路由器时，在宿主机出口上抓到隧道封装流量
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                                add_tracing_doc,
                            );
                        } else {
                            // 虚拟机或容器作为路由器时，在虚接口上抓到路由转发流量
                            // 额外追踪数据：新增的追踪数据添加MAC地址，后端通过MAC地址获取设备信息
                            return (
                                Direction::ServerGatewayToClient,
                                Direction::ClientGatewayToServer,
                                add_tracing_doc,
                            );
                        }
                    } else if is_local_mac {
                        // 本地MAC、已知单播
                        if tunnel_tier > 0 {
                            // 虚拟机作为路由器时，在宿主机出口上抓到隧道封装流量
                            if tunnel.tunnel_type == TunnelType::Ipip {
                                // 腾讯TCE的Underlay母机使用IPIP封装，外层IP为本机Underlay CVM的IP，内层IP为CLB的VIP
                                // FIXME: 目前还没有看到其他KVM使用IPIP封装的场景，这里用IPIP判断是否为TCE Underlay隧道
                                return (
                                    Direction::ClientHypervisorToServer,
                                    Direction::ServerHypervisorToClient,
                                    add_tracing_doc,
                                );
                            } else {
                                return (
                                    Direction::ServerGatewayHypervisorToClient,
                                    Direction::ClientGatewayHypervisorToServer,
                                    add_tracing_doc,
                                );
                            }
                        } else {
                            if tunnel_tier > 0 && tunnel.tunnel_type == TunnelType::TencentGre {
                                // 腾讯TCE场景，TCE-GRE隧道解封装后我们伪造了MAC地址（因此不是LocalMac）
                                // 在JNSGW场景中，Underlay CVM直接封装了GRE协议且内层IP为VIP（因此不是LocalIP）、外层IP为实IP
                                return (
                                    Direction::ClientHypervisorToServer,
                                    Direction::ServerHypervisorToClient,
                                    add_tracing_doc,
                                );
                            }
                            //其他情况:  由隧道封装的BUM包
                        }
                    } else if l3_end {
                        if is_local_mac {
                            // 交换转发：被宿主机的虚拟交换机转发的（和客户端/服务端完全一样）流量，记录为客户端宿主机、服务端宿主机
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                                add_tracing_doc,
                            );
                        }
                        //其他情况: BUM流量
                    } else {
                        if is_local_mac {
                            if is_local_ip {
                                // 容器节点作为路由器时，路由流量在宿主机出接口上直接做交换转发
                                // 举例：青云环境中，如果网卡做VXLAN Offload，流量会从vfXXX口经过，此时没有做隧道封装
                                //       POD与外部通信时在vfXXX口看到的MAC是容器节点的，因此l2End和l3End同时为假
                                //       此时只能通过isLocalIp来判断统计数据的direction
                                return (
                                    Direction::ClientHypervisorToServer,
                                    Direction::ServerHypervisorToClient,
                                    add_tracing_doc,
                                );
                            } else if tunnel_tier > 0 {
                                // 腾讯TCE的Underlay母机使用IPIP封装，外层IP为本机Underlay CVM的IP和MAC，内层IP为CLB的VIP
                                // 宽泛来讲，如果隧道内层是本机MAC、且L2End=false（即隧道外层不是本机MAC），也认为是到达了端点
                                return (
                                    Direction::ClientHypervisorToServer,
                                    Direction::ServerHypervisorToClient,
                                    add_tracing_doc,
                                );
                            } else {
                                return (
                                    Direction::ServerGatewayHypervisorToClient,
                                    Direction::ClientGatewayHypervisorToServer,
                                    add_tracing_doc,
                                );
                            }
                        }
                        //其他情况: BUM流量
                    }
                }
            }
            TridentType::TtVm => {
                if tunnel_tier == 0 && is_ep {
                    return (
                        Direction::ClientToServer,
                        Direction::ServerToClient,
                        add_tracing_doc,
                    );
                }
            }
            _ => {
                // 采集器类型不正确，不应该发生
                error!("invalid trident type, trident will stop");
                process::exit(1)
            }
        }
        (Direction::None, Direction::None, false)
    }

    const FLOW_METRICS_PEER_SRC: usize = 0;
    const FLOW_METRICS_PEER_DST: usize = 1;

    let flow_key = &flow.flow_key;

    // Workload和容器采集器需采集loopback口流量
    if flow_key.mac_src == flow_key.mac_dst {
        match trident_type {
            TridentType::TtPublicCloud
            | TridentType::TtPhysicalMachine
            | TridentType::TtHostPod
            | TridentType::TtVmPod => {
                return (Direction::LocalToLocal, Direction::None, false);
            }
            _ => (),
        }
    }

    // 全景图统计
    let tunnel = &flow.tunnel;
    let src_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
    let dst_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
    let is_vip = src_ep.is_vip || dst_ep.is_vip;
    let (mut src_direct, _, is_extra_tracing_doc0) = inner(
        flow_key.tap_type,
        tunnel,
        src_ep.is_l2_end,
        src_ep.is_l3_end,
        is_vip,
        true,
        src_ep.is_local_mac,
        src_ep.is_local_ip,
        src_ep.l3_epc_id,
        cloud_gateway_traffic,
        trident_type,
    );
    let (_, mut dst_direct, is_extra_tracing_doc1) = inner(
        flow_key.tap_type,
        tunnel,
        dst_ep.is_l2_end,
        dst_ep.is_l3_end,
        is_vip,
        MacAddr::is_unicast(flow_key.mac_dst),
        dst_ep.is_local_mac,
        dst_ep.is_local_ip,
        dst_ep.l3_epc_id,
        cloud_gateway_traffic,
        trident_type,
    );
    // 双方向都有统计位置优先级为：client/server侧 > L2End侧 > IsLocalMac侧 > 其他
    if src_direct != Direction::None && dst_direct != Direction::None {
        if (src_direct == Direction::ClientToServer || src_ep.is_l2_end)
            && dst_direct != Direction::ServerToClient
        {
            dst_direct = Direction::None;
        } else if (dst_direct == Direction::ServerToClient || dst_ep.is_l2_end)
            && src_direct != Direction::ClientToServer
        {
            src_direct = Direction::None;
        } else if src_ep.is_local_mac {
            dst_direct = Direction::None;
        } else if dst_ep.is_local_mac {
            src_direct = Direction::None;
        }
    }

    (
        src_direct,
        dst_direct,
        is_extra_tracing_doc0 || is_extra_tracing_doc1,
    )
}

// 生成32位flowID,确保在1分钟内1个thread的flowID不重复
pub fn get_uniq_flow_id_in_one_minute(flow_id: u64) -> u64 {
    // flowID中时间低8位可保证1分钟内时间的唯一，counter可保证一秒内流的唯一性（假设fps < 2^24）
    (flow_id >> 32 & 0xff << 24) | (flow_id & COUNTER_FLOW_ID_MASK)
}
