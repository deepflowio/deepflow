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

package datatype

import (
	"net"

	"github.com/deepflowio/deepflow/message/trident"
)

const (
	CIDR_TYPE_WAN = uint8(trident.CidrType_WAN)
	CIDR_TYPE_LAN = uint8(trident.CidrType_LAN)
)

// IsVIP为true时不影响cidr epcid表的建立, 但是会单独建立VIP表
type Cidr struct {
	IpNet    *net.IPNet
	TunnelId uint32
	EpcId    int32
	Type     uint8
	IsVIP    bool
	RegionId uint32
}
