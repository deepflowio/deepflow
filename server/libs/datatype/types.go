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
	. "encoding/binary"
)

type PacketFlag uint16

func (f PacketFlag) IsSet(flag PacketFlag) bool {
	return f&flag != 0
}

const (
	CFLAG_MAC0 PacketFlag = 1 << iota
	CFLAG_MAC1
	CFLAG_VLANTAG
	CFLAG_HEADER_TYPE

	CFLAG_IP0
	CFLAG_IP1
	CFLAG_PORT0
	CFLAG_PORT1

	CFLAG_TTL
	CFLAG_FLAGS_FRAG_OFFSET
	CFLAG_DATAOFF_IHL

	PFLAG_SRC_L3ENDPOINT
	PFLAG_DST_L3ENDPOINT
	PFLAG_SRC_ENDPOINT
	PFLAG_DST_ENDPOINT
	PFLAG_TUNNEL

	PFLAG_NONE PacketFlag = 0
	CFLAG_FULL            = 0x7FF
)

type IPv4Int = uint32 // not native byte order

type MacInt = uint64 // not native byte order

func MacIntFromBytes(bytes []byte) MacInt {
	return uint64(BigEndian.Uint32(bytes))<<16 | uint64(BigEndian.Uint16(bytes[4:]))
}
