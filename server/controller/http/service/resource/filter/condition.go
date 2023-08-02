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

func (cf *ConditionFilter) GetFilterConditions() common.FilterConditions {
	return cf.Condition.GetFilterConditions()
}

type Condition interface {
	Keep(v common.ResponseElem) bool
	GetFilterConditions() common.FilterConditions
}

var LOGICAL_AND = "AND"
var LOGICAL_OR = "OR"

type CombinedConditionComponent struct {
	Conditions        []Condition
	InitSkippedFields []string
}

func NewCombinedCondition() *CombinedConditionComponent {
	return new(CombinedConditionComponent)
}

func (cc *CombinedConditionComponent) Init(fcs common.FilterConditions) {
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
			t := reflect.TypeOf(v)
			switch t.Kind() {
			case reflect.Slice:
				switch t.Elem().Kind() {
				case reflect.Interface:
					vs := v.([]interface{})
					if len(vs) == 0 {
						continue
					}
					switch vs[0].(type) {
					// TODO use structs package?
					// the json package in the Go language serializes the numeric types (integers, floats, etc.) stored in the null interface to the float64 type.
					// that is, int values in struct will become float64 in converted map.
					case float64:
						cc.TryAppendIntFieldCondition(NewIN[float64](k, vs))
					case string:
						cc.TryAppendStringFieldCondition(NewIN[string](k, vs))
					}
				default:
				}
			default:
			}
		}
	}
}

func (cc *CombinedConditionComponent) AppendCondition(c Condition) {
	cc.Conditions = append(cc.Conditions, c)
}

func (cc *CombinedConditionComponent) TryAppendIntFieldCondition(fc FieldCondition[float64]) {
	if len(fc.GetValue()) > 0 {
		cc.Conditions = append(cc.Conditions, fc)
	}
}

func (cc *CombinedConditionComponent) TryAppendStringFieldCondition(fc FieldCondition[string]) {
	if len(fc.GetValue()) > 0 {
		cc.Conditions = append(cc.Conditions, fc)
	}
}

type AND struct {
	CombinedConditionComponent
}

func NewAND() *AND {
	return &AND{CombinedConditionComponent{}}
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

func (a *AND) GetFilterConditions() common.FilterConditions {
	result := make(common.FilterConditions)
	for _, c := range a.Conditions {
		for ck, cv := range c.GetFilterConditions() {
			result[ck] = cv
		}
	}
	return common.FilterConditions{LOGICAL_AND: result}
}

type OR struct {
	CombinedConditionComponent
}

func NewOR() *OR {
	return &OR{CombinedConditionComponent{}}
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

func (o *OR) GetFilterConditions() common.FilterConditions {
	result := make(common.FilterConditions)
	for _, c := range o.Conditions {
		for ck, cv := range c.GetFilterConditions() {
			result[ck] = cv
		}
	}
	return common.FilterConditions{LOGICAL_OR: result}
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

func (f *FieldConditionBase[T]) GetFilterConditions() common.FilterConditions {
	result := make(common.FilterConditions)
	result[f.Key] = f.Value
	return result
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

func NewIN[T comparable](key string, value []interface{}) *IN[T] {
	return &IN[T]{
		FieldConditionBase[T]{
			key,
			func(v []interface{}) []T {
				r := make([]T, 0)
				for _, i := range v {
					r = append(r, i.(T))
				}
				return r
			}(value),
		},
	}
}

// TODO better
func ConvertValueToSlice[T comparable](value interface{}) []T {
	result := make([]T, 0)
	t := reflect.TypeOf(value)
	switch t.Kind() {
	case reflect.Slice:
		switch t.Elem().Kind() {
		case reflect.Interface:
			vs := value.([]interface{})
			if len(vs) == 0 {
				return result
			}
			switch vs[0].(type) {
			case T:
				return func(v []interface{}) []T {
					r := make([]T, 0)
					for _, i := range v {
						r = append(r, i.(T))
					}
					return r
				}(vs)
			}
		default:
			return result
		}
	default:
		return result
	}
	return result
}
