/**
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

package generator

import (
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type AZ struct {
	FilterGeneratorComponent
}

func NewAZ() *AZ {
	g := new(AZ)
	g.SetNonAdminDropAll()
	g.SetConditionConvertor(g)
	return g
}

func (p *AZ) conditionsMapToStruct(fcs common.FilterConditions) filter.Condition {
	c := filter.NewAND()
	c.InitSkippedFields = []string{"ANALYZER_IP", "CONTROLLER_IP"}
	c.Init(fcs)
	if ips, ok := fcs["ANALYZER_IP"]; ok {
		c.TryAppendStringFieldCondition(NewAnalyzerIPCondition("ANALYZER_IP", filter.ConvertValueToSlice[string](ips)))
	}
	if ips, ok := fcs["CONTROLLER_IP"]; ok {
		c.TryAppendStringFieldCondition(NewControllerIPCondition("CONTROLLER_IP", filter.ConvertValueToSlice[string](ips)))
	}
	return c
}

func (p *AZ) userPermittedResourceToConditions(upr *UserPermittedResource) (common.FilterConditions, bool) {
	return nil, false
}

type AnalyzerIPCondition struct {
	filter.FieldConditionBase[string]
}

func NewAnalyzerIPCondition(key string, value []string) *AnalyzerIPCondition {
	return &AnalyzerIPCondition{filter.FieldConditionBase[string]{Key: key, Value: value}}
}

func (p *AnalyzerIPCondition) Keep(v common.ResponseElem) bool {
	ips := v["ANALYZER_IPS"].([]string)
	for _, item := range ips {
		if slices.Contains(p.Value, item) {
			return true
		}
	}
	return false
}

type ControllerIPCondition struct {
	filter.FieldConditionBase[string]
}

func NewControllerIPCondition(key string, value []string) *ControllerIPCondition {
	return &ControllerIPCondition{filter.FieldConditionBase[string]{Key: key, Value: value}}
}

func (p *ControllerIPCondition) Keep(v common.ResponseElem) bool {
	ips := v["CONTROLLER_IPS"].([]string)
	for _, item := range ips {
		if slices.Contains(p.Value, item) {
			return true
		}
	}
	return false
}
