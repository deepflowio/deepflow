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

use std::net::IpAddr;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::af_packet::bpf::*;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::common::{
    enums::EthernetType, ETH_TYPE_LEN, ETH_TYPE_OFFSET, GRE4_PROTO_OFFSET, GRE6_PROTO_OFFSET,
    GRE_PROTO_LEN, IPV4_ADDR_LEN, IPV4_DST_OFFSET, IPV4_FLAGS_FRAG_OFFSET_LEN, IPV4_FLAGS_OFFSET,
    IPV4_PROTO_LEN, IPV4_PROTO_OFFSET, IPV4_SRC_OFFSET, IPV6_DST_OFFSET, IPV6_PROTO_LEN,
    IPV6_PROTO_OFFSET, IPV6_SRC_OFFSET, PORT_LEN, TCP6_DST_OFFSET, TCP6_SRC_OFFSET, TCP_DST_OFFSET,
    TCP_SRC_OFFSET, UDP6_DST_OFFSET, UDP6_SRC_OFFSET, UDP_DST_OFFSET, UDP_SRC_OFFSET,
    VLAN_HEADER_SIZE, VXLAN6_FLAGS_OFFSET, VXLAN_FLAGS_OFFSET,
};
use crate::common::{enums::IpProtocol, erspan::GRE_PROTO_ERSPAN_III};
#[cfg(any(target_os = "linux", target_os = "android"))]
use public::enums::LinuxSllPacketType::Outgoing;

#[cfg(any(target_os = "linux", target_os = "android"))]
type JumpModifier = fn(jumpIf: JumpIf, index: usize, total: usize) -> JumpIf;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Default)]
struct BpfBuilder {
    ins: Vec<BpfSyntax>,
    modifiers: Vec<Option<JumpModifier>>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl BpfBuilder {
    fn appends(&mut self, syntaxs: &mut Vec<BpfSyntax>) -> &mut Self {
        for syntax in syntaxs {
            self.append(syntax.clone());
        }
        return self;
    }

    fn append(&mut self, syntax: BpfSyntax) -> &mut Self {
        self.ins.push(syntax);
        self.modifiers.push(None);
        return self;
    }

    fn branch(&mut self, jump: JumpIf, modifier: JumpModifier) -> &mut Self {
        self.ins.push(BpfSyntax::JumpIf(jump));
        self.modifiers.push(Some(modifier));
        return self;
    }

    fn build(&mut self) -> Vec<BpfSyntax> {
        for (i, modifier) in self.modifiers.iter().enumerate() {
            if modifier.is_none() {
                continue;
            }
            let modifier = modifier.unwrap();
            match self.ins[i] {
                BpfSyntax::JumpIf(e) => {
                    self.ins[i] = BpfSyntax::JumpIf(modifier(e, i, self.ins.len()))
                }
                _ => continue,
            }
        }
        return self.ins.clone();
    }
}

pub(crate) struct Builder {
    pub is_ipv6: bool,
    pub vxlan_flags: u8,
    pub npb_port: u16,
    pub controller_port: u16,
    pub analyzer_port: u16,
    pub proxy_controller_port: u16,
    pub controller_tls_port: u16,
    pub analyzer_source_ip: IpAddr,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Builder {
    fn drop_modifier(mut jump_if: JumpIf, index: usize, total: usize) -> JumpIf {
        let remain = total - (index + 1);
        if remain == 1 {
            jump_if.skip_false = 1;
        } else {
            jump_if.skip_true = (remain - 1) as u8;
        }
        return jump_if;
    }

    fn bypass_modifier(mut jump_if: JumpIf, index: usize, total: usize) -> JumpIf {
        jump_if.skip_true = (total - (index + 1)) as u8;
        return jump_if;
    }

    // 仅过滤单个vlan头
    fn skip_ethernet(&self) -> BpfBuilder {
        let mut bpf_builder = BpfBuilder::default();
        let eth_type = if self.is_ipv6 {
            u16::from(EthernetType::IPV6) as u32
        } else {
            u16::from(EthernetType::IPV4) as u32
        };

        bpf_builder
            .append(BpfSyntax::LoadAbsolute(LoadAbsolute {
                off: ETH_TYPE_OFFSET as u32,
                size: ETH_TYPE_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u16::from(EthernetType::DOT1Q) as u32,
                skip_true: 2,
                skip_false: 0,
            }))
            .append(BpfSyntax::LoadConstant(LoadConstant {
                dst: Register::RegX,
                val: VLAN_HEADER_SIZE as u32,
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: ETH_TYPE_OFFSET as u32,
                size: ETH_TYPE_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: eth_type,
                    ..Default::default()
                },
                Self::bypass_modifier,
            );
        if !self.is_ipv6 {
            bpf_builder
                .append(BpfSyntax::LoadIndirect(LoadIndirect {
                    off: IPV4_FLAGS_OFFSET as u32,
                    size: IPV4_FLAGS_FRAG_OFFSET_LEN as u32,
                }))
                .append(BpfSyntax::ALUOpConstant(ALUOpConstant {
                    op: ALU_OP_AND,
                    val: 0x1fff,
                }))
                .branch(
                    JumpIf {
                        cond: JumpTest::JumpNotEqual, // 分片包直接采集
                        val: 0,
                        ..Default::default()
                    },
                    Self::bypass_modifier,
                );
        }
        return bpf_builder;
    }

    fn skip_ipv4_npb(&self) -> Vec<BpfSyntax> {
        let mut bpf_builder = BpfBuilder::default();

        bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV4_PROTO_OFFSET as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::UDP) as u32,
                skip_true: 4,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.npb_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: VXLAN_FLAGS_OFFSET as u32,
                size: 1,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: self.vxlan_flags as u32,
                skip_true: 8,
                skip_false: 9,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::GRE) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: GRE4_PROTO_OFFSET as u32,
                size: GRE_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: GRE_PROTO_ERSPAN_III as u32,
                skip_true: 5,
                skip_false: 6,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::TCP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: self.npb_port as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.npb_port as u32,
                skip_true: 1,
                ..Default::default()
            }))
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        return bpf_builder.build();
    }

    fn skip_ipv6_npb(&self) -> Vec<BpfSyntax> {
        let mut bpf_builder = BpfBuilder::default();

        bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV6_PROTO_OFFSET as u32,
                size: IPV6_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::UDP) as u32,
                skip_true: 4,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP6_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.npb_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: VXLAN6_FLAGS_OFFSET as u32,
                size: 1,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: self.vxlan_flags as u32,
                skip_true: 8,
                skip_false: 9,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::GRE) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: GRE6_PROTO_OFFSET as u32,
                size: GRE_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: GRE_PROTO_ERSPAN_III as u32,
                skip_true: 5,
                skip_false: 6,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::TCP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP6_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: self.npb_port as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP6_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.npb_port as u32,
                skip_true: 1,
                ..Default::default()
            }))
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        return bpf_builder.build();
    }

    fn skip_controller(&self) -> Vec<BpfSyntax> {
        let mut bpf_builder = BpfBuilder::default();
        let (protocol_offset, tcp_src_port, tcp_dst_port) = if self.is_ipv6 {
            (
                IPV6_PROTO_OFFSET as u32,
                TCP6_SRC_OFFSET as u32,
                TCP6_DST_OFFSET as u32,
            )
        } else {
            (
                IPV4_PROTO_OFFSET as u32,
                TCP_SRC_OFFSET as u32,
                TCP_DST_OFFSET as u32,
            )
        };

        bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: protocol_offset as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::TCP) as u32,
                skip_false: 1,
                ..Default::default()
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::UDP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: tcp_src_port,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.controller_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.controller_tls_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.proxy_controller_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: tcp_dst_port as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.controller_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.controller_tls_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: self.proxy_controller_port as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        return bpf_builder.build();
    }

    fn skip_ipv6_tsdb(&self) -> Vec<BpfSyntax> {
        let mut src_bpf_builder = BpfBuilder::default();

        let ip_int = match self.analyzer_source_ip {
            IpAddr::V4(_) => panic!("analyzer ip {:?} type error.", &self.analyzer_source_ip),
            IpAddr::V6(i) => u128::from_be_bytes(i.octets()),
        };

        for (i, offset) in [0usize, 4, 8, 12].iter().enumerate() {
            src_bpf_builder
                .append(BpfSyntax::LoadIndirect(LoadIndirect {
                    off: (IPV6_SRC_OFFSET + offset) as u32,
                    size: IPV4_ADDR_LEN as u32,
                }))
                .branch(
                    JumpIf {
                        cond: JumpTest::JumpNotEqual,
                        val: ((ip_int >> ((3 - i) * 32)) & 0xffffffff) as u32,
                        ..Default::default()
                    },
                    Self::bypass_modifier,
                );
        }

        src_bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV6_PROTO_OFFSET as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::TCP) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP6_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.analyzer_port as u32,
                skip_true: 4,
                skip_false: 3,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::UDP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP6_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.analyzer_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        let mut dst_bpf_builder = BpfBuilder::default();

        for (i, offset) in [0usize, 4, 8, 12].iter().enumerate() {
            dst_bpf_builder
                .append(BpfSyntax::LoadIndirect(LoadIndirect {
                    off: (IPV6_DST_OFFSET + offset) as u32,
                    size: IPV4_ADDR_LEN as u32,
                }))
                .branch(
                    JumpIf {
                        cond: JumpTest::JumpNotEqual,
                        val: ((ip_int >> ((3 - i) * 32)) & 0xffffffff) as u32,
                        ..Default::default()
                    },
                    Self::bypass_modifier,
                );
        }

        dst_bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV6_PROTO_OFFSET as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::TCP) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP6_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.analyzer_port as u32,
                skip_true: 4,
                skip_false: 3,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::UDP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP6_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.analyzer_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        let mut syntax = src_bpf_builder.build();
        syntax.append(&mut dst_bpf_builder.build());
        return syntax;
    }

    fn skip_ipv4_tsdb(&self) -> Vec<BpfSyntax> {
        let mut src_bpf_builder = BpfBuilder::default();

        let ip_int = match self.analyzer_source_ip {
            IpAddr::V4(i) => u32::from(i),
            IpAddr::V6(_) => panic!("analyzer ip {:?} type error.", &self.analyzer_source_ip),
        };

        src_bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV4_SRC_OFFSET as u32,
                size: IPV4_ADDR_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: ip_int as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV4_PROTO_OFFSET as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::TCP) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.analyzer_port as u32,
                skip_true: 4,
                skip_false: 3,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::UDP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP_DST_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.analyzer_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        let mut dst_bpf_builder = BpfBuilder::default();

        dst_bpf_builder
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV4_DST_OFFSET as u32,
                size: IPV4_ADDR_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: ip_int as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV4_PROTO_OFFSET as u32,
                size: IPV4_PROTO_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u8::from(IpProtocol::TCP) as u32,
                skip_true: 2,
                ..Default::default()
            }))
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: TCP_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .append(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: self.analyzer_port as u32,
                skip_true: 4,
                skip_false: 3,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: u8::from(IpProtocol::UDP) as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadIndirect(LoadIndirect {
                off: UDP_SRC_OFFSET as u32,
                size: PORT_LEN as u32,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: self.analyzer_port as u32,
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));

        let mut syntax = src_bpf_builder.build();
        syntax.append(&mut dst_bpf_builder.build());
        return syntax;
    }

    fn skip_lo_tx(&self) -> Vec<BpfSyntax> {
        let mut lo_tx_builder = BpfBuilder::default();

        lo_tx_builder
            .append(BpfSyntax::LoadExtension(LoadExtension {
                num: Extension::ExtInterfaceIndex,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpNotEqual,
                    val: 1, // The ifIndex of the lo must be 1
                    ..Default::default()
                },
                Self::bypass_modifier,
            )
            .append(BpfSyntax::LoadExtension(LoadExtension {
                num: Extension::ExtType,
            }))
            .branch(
                JumpIf {
                    cond: JumpTest::JumpEqual,
                    val: Outgoing as u32,
                    ..Default::default()
                },
                Self::drop_modifier,
            )
            .append(BpfSyntax::RetConstant(RetConstant { val: 0 }));
        return lo_tx_builder.build();
    }

    fn build_ipv4_syntax(self, bpf_builder: &mut BpfBuilder) -> Vec<BpfSyntax> {
        // 不采集和控制器通信的流量
        bpf_builder.appends(&mut self.skip_controller());
        // 不采集和TSDB通信的流量
        bpf_builder.appends(&mut self.skip_ipv4_tsdb());
        // 不采集分发流量
        bpf_builder.appends(&mut self.skip_ipv4_npb());

        return bpf_builder.build();
    }

    fn build_ipv6_syntax(self, bpf_builder: &mut BpfBuilder) -> Vec<BpfSyntax> {
        // 不采集和控制器通信的流量
        bpf_builder.appends(&mut self.skip_controller());
        // 不采集和TSDB通信的流量
        bpf_builder.appends(&mut self.skip_ipv6_tsdb());
        // 不采集分发流量
        bpf_builder.appends(&mut self.skip_ipv6_npb());

        return bpf_builder.build();
    }

    pub fn build_pcap_syntax(self) -> Vec<BpfSyntax> {
        let mut bpf_builder = self.skip_ethernet();
        // 不采集器lo TX方向流量
        let mut lo_bpf = self.skip_lo_tx();
        if self.is_ipv6 {
            lo_bpf.append(&mut self.build_ipv6_syntax(&mut bpf_builder));
        } else {
            lo_bpf.append(&mut self.build_ipv4_syntax(&mut bpf_builder));
        }
        return lo_bpf;
    }
}

impl Builder {
    pub fn build_pcap_syntax_to_str(&self) -> String {
        let mut conditions = vec![];
        let ip_version = if self.is_ipv6 { "ip6" } else { "ip" };

        // 不采集和控制器通信的流量
        conditions.push(format!(
            "not ({} and tcp and (src port {} or {} or {}))",
            ip_version, self.controller_port, self.controller_tls_port, self.proxy_controller_port
        ));
        conditions.push(format!(
            "not ({} and tcp and (dst port {} or {} or {}))",
            ip_version, self.controller_port, self.controller_tls_port, self.proxy_controller_port
        ));

        // 不采集和TSDB通信的流量
        conditions.push(format!(
            "not ({} and src host {} and dst port {})",
            ip_version, self.analyzer_source_ip, self.analyzer_port
        ));
        conditions.push(format!(
            "not ({} and dst host {} and src port {})",
            ip_version, self.analyzer_source_ip, self.analyzer_port
        ));

        // 不采集分发的VXLAN流量
        conditions.push(format!(
            "not (udp and dst port {} and udp[8:1]={:#x})",
            self.npb_port, self.vxlan_flags
        ));

        // 不采集分发的TCP流量
        conditions.push(format!("not (tcp and port {})", self.npb_port,));

        // 不采集分发的ERSPANIII
        conditions.push(format!(
            "not (ip[9:1]={:#x} and ip[22:2]={:#x})",
            u8::from(IpProtocol::GRE),
            GRE_PROTO_ERSPAN_III
        ));
        conditions.push(format!(
            "not (ip6[6:1]={:#x} and ip6[42:2]={:#x})",
            u8::from(IpProtocol::GRE),
            GRE_PROTO_ERSPAN_III
        ));

        conditions.join(" and ")
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_bpf_syntax() {
        let builder = Builder {
            is_ipv6: false,
            vxlan_flags: 0xff,
            npb_port: 1122,
            controller_port: 3344,
            controller_tls_port: 5566,
            proxy_controller_port: 7788,
            analyzer_port: 8899,
            analyzer_source_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
        };

        let syntax = builder.build_pcap_syntax();
        let output = syntax
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let except = [
            "ld #ifidx",
            "jneq #1,3",
            "ld #type",
            "jneq #4,1",
            "ret #0",
            "ldh [12]",
            "jneq #33024,2",
            "ldx #4",
            "ldh [x + 12]",
            "jneq #2048,50",
            "ldh [x + 20]",
            "and #8191",
            "jneq #0,47",
            "ldb [x + 23]",
            "jeq #6,1",
            "jneq #17,9",
            "ldh [x + 34]",
            "jeq #3344,6",
            "jeq #5566,5",
            "jeq #7788,4",
            "ldh [x + 36]",
            "jeq #3344,2",
            "jeq #5566,1",
            "jneq #7788,1",
            "ret #0",
            "ld [x + 26]",
            "jneq #16909060,8",
            "ldb [x + 23]",
            "jneq #6,2",
            "ldh [x + 36]",
            "jneq #8899,4,3",
            "jneq #17,3",
            "ldh [x + 36]",
            "jneq #8899,1",
            "ret #0",
            "ld [x + 30]",
            "jneq #16909060,8",
            "ldb [x + 23]",
            "jneq #6,2",
            "ldh [x + 34]",
            "jneq #8899,4,3",
            "jneq #17,3",
            "ldh [x + 34]",
            "jneq #8899,1",
            "ret #0",
            "ldb [x + 23]",
            "jneq #17,4",
            "ldh [x + 36]",
            "jneq #1122,11",
            "ldb [x + 42]",
            "jeq #255,8,9",
            "jneq #47,2",
            "ldh [x + 36]",
            "jeq #8939,5,6",
            "jneq #6,5",
            "ldh [x + 36]",
            "jeq #1122,2",
            "ldh [x + 34]",
            "jneq #1122,1",
            "ret #0",
        ];

        for (i, line) in output.iter().enumerate() {
            assert_eq!(line, except[i]);
        }
    }

    #[test]
    fn ipv6_bpf_syntax() {
        let builder = Builder {
            is_ipv6: true,
            vxlan_flags: 0xff,
            npb_port: 1122,
            controller_port: 3344,
            controller_tls_port: 5566,
            proxy_controller_port: 7788,
            analyzer_port: 8899,
            analyzer_source_ip: "9999:aaaa:bbbb:cccc:dddd:eeee:ffff:0000"
                .parse::<IpAddr>()
                .unwrap(),
        };

        let syntax = builder.build_pcap_syntax();
        let output = syntax
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        output.iter().for_each(|x| println!("\"{}\",", x));

        let except = [
            "ld #ifidx",
            "jneq #1,3",
            "ld #type",
            "jneq #4,1",
            "ret #0",
            "ldh [12]",
            "jneq #33024,2",
            "ldx #4",
            "ldh [x + 12]",
            "jneq #34525,59",
            "ldb [x + 20]",
            "jeq #6,1",
            "jneq #17,9",
            "ldh [x + 54]",
            "jeq #3344,6",
            "jeq #5566,5",
            "jeq #7788,4",
            "ldh [x + 56]",
            "jeq #3344,2",
            "jeq #5566,1",
            "jneq #7788,1",
            "ret #0",
            "ld [x + 22]",
            "jneq #2576984746,14",
            "ld [x + 26]",
            "jneq #3149647052,12",
            "ld [x + 30]",
            "jneq #3722309358,10",
            "ld [x + 34]",
            "jneq #4294901760,8",
            "ldb [x + 20]",
            "jneq #6,2",
            "ldh [x + 56]",
            "jneq #8899,4,3",
            "jneq #17,3",
            "ldh [x + 56]",
            "jneq #8899,1",
            "ret #0",
            "ld [x + 38]",
            "jneq #2576984746,14",
            "ld [x + 42]",
            "jneq #3149647052,12",
            "ld [x + 46]",
            "jneq #3722309358,10",
            "ld [x + 50]",
            "jneq #4294901760,8",
            "ldb [x + 20]",
            "jneq #6,2",
            "ldh [x + 54]",
            "jneq #8899,4,3",
            "jneq #17,3",
            "ldh [x + 54]",
            "jneq #8899,1",
            "ret #0",
            "ldb [x + 20]",
            "jneq #17,4",
            "ldh [x + 56]",
            "jneq #1122,11",
            "ldb [x + 62]",
            "jeq #255,8,9",
            "jneq #47,2",
            "ldh [x + 56]",
            "jeq #8939,5,6",
            "jneq #6,5",
            "ldh [x + 56]",
            "jeq #1122,2",
            "ldh [x + 54]",
            "jneq #1122,1",
            "ret #0",
        ];

        for (i, line) in output.iter().enumerate() {
            assert_eq!(line, except[i]);
        }
    }
}
