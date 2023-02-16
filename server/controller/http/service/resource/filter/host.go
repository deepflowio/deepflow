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

package filter

import (
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type HostFilterGenerator struct{}

func NewHostFilterGenerator() *HostFilterGenerator {
	return new(HostFilterGenerator)
}

func (p *HostFilterGenerator) Generate(urlInfo *model.URLInfo, userInfo *model.UserInfo) []Filter {
	var fs []Filter
	if f := p.generateConditionalFilter(urlInfo, userInfo); f != nil {
		fs = append(fs, f)
	} else {
		return nil
	}
	if f := p.generatePartialFilter(urlInfo, userInfo); f != nil { // TODO use next?
		fs = append(fs, f)
	}
	return fs
}

func (p *HostFilterGenerator) generateConditionalFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter {
	fcs := urlInfo.FilterConditions
	if urlInfo.UserID != 0 || userInfo != nil {
		if ufcs := p.generateUserCondition(urlInfo, userInfo); ufcs != nil {
			for k, v := range ufcs {
				fcs[k] = v
			}
		}
	}
	if len(fcs) == 0 {
		return nil
	}
	return NewHostConditionalFilter(FilterConditions{LOGICAL_AND: fcs})
}

func (p *HostFilterGenerator) generateUserCondition(urlInfo *model.URLInfo, userInfo *model.UserInfo) FilterConditions {
	return nil
}

func (p *HostFilterGenerator) generatePartialFilter(urlInfo *model.URLInfo, userInfo *model.UserInfo) Filter {
	f := new(PartialFilter)
	if len(urlInfo.IncludedFields) != 0 {
		f.includedFields = urlInfo.IncludedFields
	}
	if !IsAdmin(userInfo.Type) {
		f.excludedFields = append(f.excludedFields, p.getUserExcludeFields()...)
	}
	if len(f.excludedFields) == 0 && len(f.includedFields) == 0 {
		return nil
	}
	return f
}

func (p *HostFilterGenerator) getUserExcludeFields() []string {
	return []string{}
}

func (p *HostFilterGenerator) getParentResourceTypes() []string {
	return []string{}
}

type HostConditionalFilter struct {
	ConditionalFilter
	CombinedCondition
}

func NewHostConditionalFilter(cm FilterConditions) *HostConditionalFilter {
	f := new(HostConditionalFilter)
	f.Init(cm)
	return f
}
