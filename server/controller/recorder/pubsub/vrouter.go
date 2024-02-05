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

package pubsub

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type VRouter struct {
	ResourcePubSubComponent[
		*message.VRouterAdd,
		message.VRouterAdd,
		*message.VRouterUpdate,
		message.VRouterUpdate,
		*message.VRouterFieldsUpdate,
		message.VRouterFieldsUpdate,
		*message.VRouterDelete,
		message.VRouterDelete]
}

func NewVRouter() *VRouter {
	return &VRouter{
		ResourcePubSubComponent[
			*message.VRouterAdd,
			message.VRouterAdd,
			*message.VRouterUpdate,
			message.VRouterUpdate,
			*message.VRouterFieldsUpdate,
			message.VRouterFieldsUpdate,
			*message.VRouterDelete,
			message.VRouterDelete,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeVRouter),
			resourceType:    common.RESOURCE_TYPE_VROUTER_EN,
		},
	}
}
