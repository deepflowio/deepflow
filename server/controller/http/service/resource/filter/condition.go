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

package filter

import (
	"reflect"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type ConditionFilter struct {
	Condition Condition
}

func NewConditionFilter(condition Condition) *ConditionFilter {
	return &ConditionFilter{Condition: condition}
}

// Filter implements Filter interface
func (cf *ConditionFilter) Filter(data []common.ResponseElem) ([]common.ResponseElem, error) {
	var result []common.ResponseElem
	for _, d := range data {
		if cf.Condition.Keep(d) {
			result = append(result, d)
		}
	}
	return result, nil
}

type Condition interface {
	Keep(v common.ResponseElem) bool
}

var LOGICAL_AND = "AND"
var LOGICAL_OR = "OR"

type CombinedConditionBase struct {
	Conditions        []Condition
	InitSkippedFields []string
}

func NewCombinedCondition() *CombinedConditionBase {
	return new(CombinedConditionBase)
}

func (cc *CombinedConditionBase) Init(fcs common.FilterConditions) {
	for k, v := range fcs {
		switch k {
		case LOGICAL_AND:
			and := NewAND()
			and.Init(v.(common.FilterConditions))
			cc.Conditions = append(cc.Conditions, and)
		case LOGICAL_OR:
			or := NewOR()
			or.Init(v.(common.FilterConditions))
			cc.Conditions = append(cc.Conditions, or)
		default:
			if slices.Contains(cc.InitSkippedFields, k) {
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

func (cc *CombinedConditionBase) AppendCondition(c Condition) {
	cc.Conditions = append(cc.Conditions, c)
}

func (cc *CombinedConditionBase) TryAppendIntFieldCondition(fc FieldCondition[int]) {
	if len(fc.GetValue()) > 0 {
		cc.Conditions = append(cc.Conditions, fc)
	}
}

func (cc *CombinedConditionBase) TryAppendStringFieldCondition(fc FieldCondition[string]) {
	if len(fc.GetValue()) > 0 {
		cc.Conditions = append(cc.Conditions, fc)
	}
}

type AND struct {
	CombinedConditionBase
}

func NewAND() *AND {
	return &AND{CombinedConditionBase{}}
}

// Keep implements Condition interface
func (a *AND) Keep(v common.ResponseElem) bool {
	for _, f := range a.Conditions {
		if !f.Keep(v) {
			return false
		}
	}
	return true
}

type OR struct {
	CombinedConditionBase
}

func NewOR() *OR {
	return &OR{CombinedConditionBase{}}
}

// Keep implements Condition interface
func (o *OR) Keep(v common.ResponseElem) bool {
	for _, f := range o.Conditions {
		if f.Keep(v) {
			return true
		}
	}
	return false
}

// FieldCondition defines the interface for a specific field
type FieldCondition[T comparable] interface {
	Condition
	GetKey() string
	GetValue() []T
}

type FieldConditionBase[T comparable] struct {
	Key   string
	Value []T
}

func (f *FieldConditionBase[T]) GetKey() string {
	return f.Key
}

func (f *FieldConditionBase[T]) GetValue() []T {
	return f.Value
}

// IN is used to check whether the value of a field exists in the condition values
type IN[T comparable] struct {
	FieldConditionBase[T]
}

// Keep implements Condition interface
func (i *IN[T]) Keep(e common.ResponseElem) bool {
	v, ok := e[i.Key]
	if !ok {
		return false
	}
	if slices.Contains(i.Value, v.(T)) {
		return true
	}
	return false
}

func NewIN[T comparable](key string, value []T) *IN[T] {
	return &IN[T]{FieldConditionBase[T]{key, value}}
}
