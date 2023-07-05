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

package model

type RefreshCacheParam struct {
	RefreshCache bool `schema:"refresh_cache,omitempty"`
}

type IncludedFieldsParam struct {
	IncludedFields []string `schema:"field,omitempty"`
}

// VMQuery defines supported field in query string, and uses tag (schema) to define the parameter name
// 定义可支持 query 字段，使用 tag（schema）定义参数名
type VMQuery struct {
	VMQueryStoredInRedis
	RefreshCacheParam
}

// VMQueryStoredInRedis defines the fields that need to be used to build the redis cache key
// 定义需用于构建 redis 缓存 key 的字段
type VMQueryStoredInRedis struct {
	VMQueryFilterConditions
	IncludedFieldsParam
}

type HostQuery struct {
	HostQueryStoredInRedis
	RefreshCacheParam
}

type HostQueryStoredInRedis struct {
	HostQueryFilterConditions
	IncludedFieldsParam
}

type PodQuery struct {
	PodQueryStoredInRedis
	RefreshCacheParam
}

type PodQueryStoredInRedis struct {
	PodQueryFilterConditions
	IncludedFieldsParam
}
