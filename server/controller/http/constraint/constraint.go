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

package constraint

import (
	"github.com/deepflowio/deepflow/server/controller/http/model"
)

// 各资源可支持的 query 字段定义
type QueryModel interface {
	model.VMQuery | model.PodQuery | model.PodReplicaSetQuery | model.PodGroupQuery | model.PodGroupPortQuery |
		model.PodServiceQuery | model.PodServicePortQuery | model.PodIngressQuery | model.PodIngressRuleQuery |
		model.PodNodeQuery | model.PodNamespaceQuery | model.PodClusterQuery
}

// 各资源需要用于构建 redis 缓存 key 的 query 字段定义
type QueryStoredInRedisModel interface {
	model.VMQueryStoredInRedis | model.PodQueryStoredInRedis | model.PodReplicaSetQueryStoredInRedis |
		model.PodGroupQueryStoredInRedis | model.PodGroupPortQueryStoredInRedis | model.PodServiceQueryStoredInRedis |
		model.PodServicePortQueryStoredInRedis | model.PodIngressQueryStoredInRedis | model.PodIngressRuleQueryStoredInRedis |
		model.PodNodeQueryStoredInRedis | model.PodNamespaceQueryStoredInRedis | model.PodClusterQueryStoredInRedis

	GetIncludedFields() []string
	GetUserID() int
	GetFilterConditions() map[string]interface{}
}
