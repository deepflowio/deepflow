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

type DHCPPort struct {
	ResourcePubSubComponent[
		*message.DHCPPortAdd,
		message.DHCPPortAdd,
		message.AddNoneAddition,
		*message.DHCPPortUpdate,
		message.DHCPPortUpdate,
		*message.DHCPPortFieldsUpdate,
		message.DHCPPortFieldsUpdate,
		*message.DHCPPortDelete,
		message.DHCPPortDelete,
		message.DeleteNoneAddition]
}

func NewDHCPPort() *DHCPPort {
	return &DHCPPort{
		ResourcePubSubComponent[
			*message.DHCPPortAdd,
			message.DHCPPortAdd,
			message.AddNoneAddition,
			*message.DHCPPortUpdate,
			message.DHCPPortUpdate,
			*message.DHCPPortFieldsUpdate,
			message.DHCPPortFieldsUpdate,
			*message.DHCPPortDelete,
			message.DHCPPortDelete,
			message.DeleteNoneAddition,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeDHCPPort),
			resourceType:    common.RESOURCE_TYPE_DHCP_PORT_EN,
		},
	}
}
