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

package log_data

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

func IPIntToString(ipInt uint32) string {
	return net.IPv4(byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt)).String()
}

// eg. url=http://nacos:8848/nacos/v1/ns/instance/list, parse return `/nacos/v1/ns/instance/list`
func ParseUrlPath(rawURL string) (string, error) {
	parts := strings.SplitN(rawURL, "://", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid URL format")
	}
	pathStart := strings.Index(parts[1], "/")
	if pathStart == -1 {
		return "/", nil
	}

	return parts[1][pathStart:], nil
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func GetBuffer() *bytes.Buffer {
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	return buffer
}

func PutBuffer(buffer *bytes.Buffer) {
	bufferPool.Put(buffer)
}

func ParseL7Protocol(l7ProtocolStr string, version string) (uint8, uint8) {
	var l7Protocol uint8 = 0
	var isTLS uint8 = 0
	if len(l7ProtocolStr) > 0 {
		l7ProtocolStrLower := strings.ToLower(l7ProtocolStr)
		if strings.Contains(l7ProtocolStrLower, "https") {
			isTLS = 1
		}
		for l7ProtocolStr, l7ProtocolMap := range datatype.L7ProtocolStringMap {
			if strings.Contains(l7ProtocolStr, l7ProtocolStrLower) {
				l7Protocol = uint8(l7ProtocolMap)
				break
			}
		}
		// If the protocol name is 'http', it may be randomly matched to 'http1' or 'http2' and needs to be corrected.
		if l7Protocol == uint8(datatype.L7_PROTOCOL_HTTP_1) || l7Protocol == uint8(datatype.L7_PROTOCOL_HTTP_2) {
			if strings.HasPrefix(version, "2") {
				l7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_2)
			} else {
				l7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_1)
			}
		}
	}
	return l7Protocol, isTLS
}
