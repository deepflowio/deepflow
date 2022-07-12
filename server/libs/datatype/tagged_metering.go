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
	"fmt"
)

type TaggedMetering struct {
	Metering
	Tag
}

func (m *TaggedMetering) PacketCount() uint64 {
	return m.PacketCount0 + m.PacketCount1
}

func (m *TaggedMetering) BitCount() uint64 {
	return (m.ByteCount0 + m.ByteCount1) << 3
}

func (t *TaggedMetering) String() string {
	return fmt.Sprintf("%s\n    Tag: %+v", &t.Metering, t.Tag)
}
