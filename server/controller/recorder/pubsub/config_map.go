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

package pubsub

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ConfigMap struct {
	ResourcePubSubComponent[
		*message.AddedConfigMaps,
		message.AddedConfigMaps,
		message.AddNoneAddition,
		*message.UpdatedConfigMap,
		message.UpdatedConfigMap,
		*message.UpdatedConfigMapFields,
		message.UpdatedConfigMapFields,
		*message.DeletedConfigMaps,
		message.DeletedConfigMaps,
		message.DeleteNoneAddition]
}

func NewConfigMap() *ConfigMap {
	return &ConfigMap{
		ResourcePubSubComponent[
			*message.AddedConfigMaps,
			message.AddedConfigMaps,
			message.AddNoneAddition,
			*message.UpdatedConfigMap,
			message.UpdatedConfigMap,
			*message.UpdatedConfigMapFields,
			message.UpdatedConfigMapFields,
			*message.DeletedConfigMaps,
			message.DeletedConfigMaps,
			message.DeleteNoneAddition,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeConfigMap),
			resourceType:    common.RESOURCE_TYPE_CONFIG_MAP_EN,
		},
	}
}
