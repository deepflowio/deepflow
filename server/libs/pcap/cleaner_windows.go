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

package pcap

import (
	"time"
)

type Cleaner struct {
}

func NewCleaner(cleanPeriod time.Duration, maxDirectorySize, diskFreeSpaceMargin int64, baseDirectory string) *Cleaner {
	return &Cleaner{}
}

func (c *Cleaner) UpdatePcapDataRetention(pcapDataRetention time.Duration) {
}

func (c *Cleaner) GetPcapDataRetention() time.Duration {
	return 0
}

func (c *Cleaner) Start() {
}
