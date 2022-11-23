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

use std::fmt;

use num_enum::TryFromPrimitive;
use serde::Serialize;

use crate::proto::trident::DecapType;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, PartialOrd, TryFromPrimitive)]
#[repr(u8)]
pub enum TunnelType {
    None = DecapType::None as u8,
    Vxlan = DecapType::Vxlan as u8,
    Ipip = DecapType::Ipip as u8,
    TencentGre = DecapType::Tencent as u8,
    ErspanOrTeb = TunnelType::TencentGre as u8 + 1,
}

impl From<DecapType> for TunnelType {
    fn from(t: DecapType) -> Self {
        match t {
            DecapType::None => TunnelType::None,
            DecapType::Vxlan => TunnelType::Vxlan,
            DecapType::Ipip => TunnelType::Ipip,
            DecapType::Tencent => TunnelType::TencentGre,
        }
    }
}

impl fmt::Display for TunnelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelType::None => write!(f, "none"),
            TunnelType::Vxlan => write!(f, "VXLAN"),
            TunnelType::Ipip => write!(f, "IPIP"),
            TunnelType::TencentGre => write!(f, "GRE"),
            TunnelType::ErspanOrTeb => write!(f, "ERSPAN_TEB"),
        }
    }
}

impl Default for TunnelType {
    fn default() -> Self {
        TunnelType::None
    }
}
