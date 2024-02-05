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

type NATGateway struct {
	ResourcePubSubComponent[
		*message.NATGatewayAdd,
		message.NATGatewayAdd,
		*message.NATGatewayUpdate,
		message.NATGatewayUpdate,
		*message.NATGatewayFieldsUpdate,
		message.NATGatewayFieldsUpdate,
		*message.NATGatewayDelete,
		message.NATGatewayDelete]
}

func NewNATGateway() *NATGateway {
	return &NATGateway{
		ResourcePubSubComponent[
			*message.NATGatewayAdd,
			message.NATGatewayAdd,
			*message.NATGatewayUpdate,
			message.NATGatewayUpdate,
			*message.NATGatewayFieldsUpdate,
			message.NATGatewayFieldsUpdate,
			*message.NATGatewayDelete,
			message.NATGatewayDelete,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeNATGateway),
			resourceType:    common.RESOURCE_TYPE_NAT_GATEWAY_EN,
		},
	}
}
