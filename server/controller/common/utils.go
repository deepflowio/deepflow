/**
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

package common

import (
	"reflect"
	"time"
)

func GetVarSize(val any) (sumSize uint64) {
	vl := reflect.ValueOf(val)
	tp := reflect.TypeOf(val)
	//tp.Size() + vl.Kind()
	switch vl.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64,
		reflect.Complex128:
		return uint64(tp.Size()) //unsafe.Sizeof(val)
	case reflect.Map:
		forSize := uint64(tp.Size())
		for _, i := range vl.MapKeys() {
			forSize += GetVarSize(i.Interface()) + GetVarSize(vl.MapIndex(i).Interface())
		}
		return forSize
	case reflect.Array, reflect.Slice:
		forSize := uint64(tp.Size())
		for i := 0; i < vl.Len(); i++ {
			forSize += GetVarSize(vl.Index(i).Interface())
		}
		return forSize
		//return uint64(tp.Size()) + vl.Len()*GetVarSize(vl.Elem().Interface())//array and slice , not have Elem()
	case reflect.Chan:
		//请注意，尝试获取channel元素类型的操作（即varType.Elem()）是不允许的，因为这将导致运行时的panic。在Go中，你不能通过反射来获取channel的元素类型。
		forSize := uint64(tp.Size())
		for i := 0; i < vl.Len(); i++ {
			forSize += 0
		}
		return forSize
	case reflect.Func:
		return uint64(tp.Size())
	case reflect.Interface:
		fallthrough
	case reflect.Pointer:
		forSize := uint64(tp.Size())
		if vl.IsNil() {
			return forSize
		}
		return forSize + GetVarSize(vl.Elem().Interface())
	case reflect.String:
		forSize := uint64(tp.Size())
		for i := 0; i < vl.Len(); i++ {
			forSize += GetVarSize(vl.Index(i).Interface())
		}
		return forSize
	case reflect.Struct:
		forSize := uint64(tp.Size())
		for i := 0; i < vl.NumField(); i++ {
			tpField := tp.Field(i)
			vlField := vl.Field(i)
			if tp.Name() == "Time" && tp.PkgPath() == "time" {
				_ = &time.Time{}
				//forSize += 8*2 + GetVarSize(time.Location{})
				//forSize += 8*2 + (16 + 5) + (24 + (8 + 3) + (8 + 1)) + (24 + (8 + 1 + 2)) + (16 + 0) + 8 + 8 + (8 + (3 + 8 + 1))
				forSize += 24 //time.Time{} 基本都是空数据,就用这个; 有 time.Local的才会用到上面的这个.
				continue
			}
			if !tpField.IsExported() {
				s := uint64(vlField.Type().Size()) //uint64(tpField.Type.Size())
				forSize += s
				log.Debugf("Struct (%T)'s field(%v) not IsExported() string:%v, theSize=%v tp=%v vl=%v\n", val, i, vlField.String(), s, tpField, vlField)

				//TODO 不可导出字段,应该可以通过 unsafe 获取数据的. 不处理这个问题,无法获得真实的大小的.
				//var tp = reflect.New(tpField.Type)
				//tp.SetPointer(unsafe.Pointer(vlField.UnsafePointer()))
				//forSize += GetVarSize(tp.Interface())

				continue
			}
			if !vlField.CanInterface() {
				s := uint64(vlField.Type().Size())
				forSize += s
				log.Debugf("Struct (%T)'s field(%v) cannot string:%v theSize use :%v\n", val, i, vlField.String(), s)
				continue
			}

			switch vlField.Kind() {
			case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.UnsafePointer,
				reflect.Interface, reflect.Slice:
				if vlField.IsNil() {
					forSize += uint64(vlField.Type().Size())
					continue
				}
			}
			forSize += GetVarSize(vlField.Interface())
		}
		return forSize
	case reflect.UnsafePointer:
		forSize := uint64(tp.Size())
		return forSize
	default:
		//return 0
		log.Errorf(" %T Not support Kind %v", val, vl.Kind())
	}
	return 0
}
