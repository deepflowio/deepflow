/*
 * Copyright (c) 2023 Yunshan Networks
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

package statsd

var (
	VTapNameToCounter = make(map[string]*GetVTapWeightCounter)
)

type VTapWeightCounter struct {
	Weight            float64 `statsd:"weight"`
	IsAnalyzerChanged uint64  `statsd:"is_analyzer_changed"`
}

func NewVTapWeightCounter() *VTapWeightCounter {
	return &VTapWeightCounter{}
}

type GetVTapWeightCounter struct {
	*VTapWeightCounter
	Name string
}

func (g *GetVTapWeightCounter) GetCounter() interface{} {
	return g.VTapWeightCounter
}

func (g *GetVTapWeightCounter) Closed() bool {
	return false
}
