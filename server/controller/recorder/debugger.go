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

// 提供获取recorder内部数据的debug接口
package recorder

import (
	"reflect"

	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

func (r *Recorder) GetCache(domainLcuuid, subDomainLcuuid string) cache.Cache {
	if subDomainLcuuid != "" {
		subDomainCache, exists := r.cacheMng.SubDomainCacheMap[subDomainLcuuid]
		if exists {
			return *subDomainCache
		} else {
			return cache.Cache{}
		}
	} else {
		return *r.cacheMng.DomainCache
	}
}

func (r *Recorder) GetCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, resourceType string) map[string]interface{} {
	cache := r.GetCache(domainLcuuid, subDomainLcuuid)
	dataSetValue := reflect.ValueOf(cache.DiffBaseDataSet).Elem()
	dataSet := dataSetValue.FieldByName(resourceType).Interface()
	if dataSet == nil {
		return nil
	}
	return dataSet.(map[string]interface{})
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
	cache := r.GetCache(domainLcuuid, subDomainLcuuid)
	dataSetValue := reflect.ValueOf(cache.ToolDataSet).Elem()
	dataSet := dataSetValue.FieldByName(field).Interface()
	if dataSet == nil {
		return nil
	}
	return dataSet.(map[interface{}]interface{})
}
