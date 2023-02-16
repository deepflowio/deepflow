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
	"reflect"

	"github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type ConditionalFilter struct {
	condition Condition
}

func NewConditionalFilter(condition Condition) *ConditionalFilter {
	return &ConditionalFilter{condition: condition}
}

func (cf *ConditionalFilter) Filter(data []ResponseElem) ([]ResponseElem, error) {
	var result []ResponseElem
	for _, d := range data {
		if cf.condition.Keep(d) {
			result = append(result, d)
		}
	}
	return result, nil
}

type Condition interface {
	Keep(v ResponseElem) bool
}

var LOGICAL_AND = "AND"
var LOGICAL_OR = "OR"

type CombinedCondition struct {
	conditions    []Condition
	specialFields []string
}

func (cc *CombinedCondition) Init(fcs FilterConditions) {
	for k, v := range fcs {
		switch k {
		case LOGICAL_AND:
			and := NewAND()
			and.Init(v.(FilterConditions))
			cc.conditions = append(cc.conditions, and)
		case LOGICAL_OR:
			or := NewOR()
			or.Init(v.(FilterConditions))
			cc.conditions = append(cc.conditions, or)
		default:
			if common.Contains(cc.specialFields, k) {
				continue
			}
			value := reflect.ValueOf(v)
			if value.Kind() == reflect.Slice {
				ek := value.Type().Elem().Kind()
				if ek == reflect.Int {
					cc.TryAppendIntFieldCondition(NewIN(k, v.([]int)))
				} else if ek == reflect.String {
					cc.TryAppendStringFieldCondition(NewIN(k, v.([]string)))
				}
			}
		}
	}
}

func (cc *CombinedCondition) AppendCondition(c Condition) {
	cc.conditions = append(cc.conditions, c)
}

func (cc *CombinedCondition) TryAppendIntFieldCondition(fc FieldCondition[int]) {
	if len(fc.GetValue()) > 0 {
		cc.conditions = append(cc.conditions, fc)
	}
}

func (cc *CombinedCondition) TryAppendStringFieldCondition(fc FieldCondition[string]) {
	if len(fc.GetValue()) > 0 {
		cc.conditions = append(cc.conditions, fc)
	}
}

type AND struct {
	CombinedCondition
}

func NewAND() *AND {
	return &AND{CombinedCondition{}}
}

func (a *AND) Keep(v ResponseElem) bool {
	for _, f := range a.conditions {
		if !f.Keep(v) {
			return false
		}
	}
	return true
}

type OR struct {
	CombinedCondition
}

func NewOR() *OR {
	return &OR{CombinedCondition{}}
}

func (o *OR) Keep(v ResponseElem) bool {
	for _, f := range o.conditions {
		if f.Keep(v) {
			return true
		}
	}
	return false
}

type FieldCondition[T common.Comparable] interface {
	Condition
	GetKey() string
	GetValue() []T
}

type FieldConditionBase[T common.Comparable] struct {
	key   string
	value []T
}

func (f *FieldConditionBase[T]) GetKey() string {
	return f.key
}

func (f *FieldConditionBase[T]) GetValue() []T {
	return f.value
}

type IN[T common.Comparable] struct {
	FieldConditionBase[T]
}

func (i *IN[T]) Keep(e ResponseElem) bool {
	v, ok := e[i.key]
	if !ok {
		return false
	}
	if common.Contains(i.value, v.(T)) {
		return true
	}
	return false
}

func NewIN[T common.Comparable](key string, value []T) *IN[T] {
	return &IN[T]{FieldConditionBase[T]{key, value}}
}
