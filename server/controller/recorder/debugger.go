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

// 提供获取recorder内部数据的debug接口
package recorder

import (
	"reflect"

	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

// TODO remove
func (r *Recorder) GetCache(domainLcuuid, subDomainLcuuid string) cache.Cache {
	return cache.Cache{}
	// if subDomainLcuuid != "" {
	// 	subDomainCache, exists := r.cacheMng.SubDomainCacheMap[subDomainLcuuid]
	// 	if exists {
	// 		return *subDomainCache
	// 	} else {
	// 		return cache.Cache{}
	// 	}
	// } else {
	// 	return *r.domainRefresher.cache
	// }
}

func (r *Recorder) GetCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, resourceType string) map[string]interface{} {
	c := r.GetCache(domainLcuuid, subDomainLcuuid)
	diffBases := c.DiffBases()
	if diffBases == nil {
		return nil
	}
	method := reflect.ValueOf(diffBases).MethodByName(resourceType)
	if !method.IsValid() {
		return nil
	}
	result := method.Call(nil)
	if len(result) == 0 || result[0].IsNil() {
		return nil
	}
	getAllMethod := result[0].MethodByName("GetAll")
	if !getAllMethod.IsValid() {
		return nil
	}
	getAllResult := getAllMethod.Call(nil)
	if len(getAllResult) == 0 {
		return nil
	}
	return getAllResult[0].Interface().(map[string]interface{})
}

func (r *Recorder) GetCacheDiffBase(domainLcuuid, subDomainLcuuid, resourceType, resourceLcuuid string) interface{} {
	dataSet := r.GetCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, resourceType)
	diffBase, exists := dataSet[resourceLcuuid]
	if !exists {
		return nil
	}
	return diffBase
}

func (r *Recorder) GetToolMap(domainLcuuid, subDomainLcuuid, field string) map[interface{}]interface{} {
	c := r.GetCache(domainLcuuid, subDomainLcuuid)
	t := c.Tool()
	if t == nil {
		return nil
	}
	method := reflect.ValueOf(t).MethodByName(field)
	if !method.IsValid() {
		return nil
	}
	result := method.Call(nil)
	if len(result) == 0 || result[0].IsNil() {
		return nil
	}
	return result[0].Interface().(map[interface{}]interface{})
}
