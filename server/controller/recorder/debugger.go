// 提供获取recorder内部数据的debug接口
package recorder

import (
	"reflect"

	"server/controller/recorder/cache"
)

func (r *Recorder) GetCache(domainLcuuid, subDomainLcuuid string) cache.Cache {
	if subDomainLcuuid != "" {
		subDomainCache, _ := r.cacheMng.SubDomainCacheMap[subDomainLcuuid]
		return *subDomainCache
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
