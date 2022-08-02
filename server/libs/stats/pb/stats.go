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

package pb

import (
	"github.com/deepflowys/deepflow/server/libs/codec"
	"github.com/deepflowys/deepflow/server/libs/pool"
)

func (s *Stats) Encode(encoder *codec.SimpleEncoder) {
	encoder.WritePB(s)
	return
}

func (s *Stats) Release() {
	ReleaseDFStats(s)
}

var poolDFStats = pool.NewLockFreePool(func() interface{} {
	return &Stats{
		TagNames:           make([]string, 0, 4),
		TagValues:          make([]string, 0, 4),
		MetricsFloatNames:  make([]string, 0, 4),
		MetricsFloatValues: make([]float64, 0, 4),
	}
})

func AcquireDFStats() *Stats {
	return poolDFStats.Get().(*Stats)
}

func ReleaseDFStats(s *Stats) {
	if s == nil {
		return
	}
	s.Name = ""
	s.Timestamp = 0
	s.TagNames = s.TagNames[:0]
	s.TagValues = s.TagValues[:0]
	s.MetricsFloatNames = s.MetricsFloatNames[:0]
	s.MetricsFloatValues = s.MetricsFloatValues[:0]

	poolDFStats.Put(s)
}
