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

type LBVMConnection struct {
	ResourcePubSubComponent[
		*message.LBVMConnectionAdd,
		message.LBVMConnectionAdd,
		*message.LBVMConnectionUpdate,
		message.LBVMConnectionUpdate,
		*message.LBVMConnectionFieldsUpdate,
		message.LBVMConnectionFieldsUpdate,
		*message.LBVMConnectionDelete,
		message.LBVMConnectionDelete]
}

func NewLBVMConnection() *LBVMConnection {
	return &LBVMConnection{
		ResourcePubSubComponent[
			*message.LBVMConnectionAdd,
			message.LBVMConnectionAdd,
			*message.LBVMConnectionUpdate,
			message.LBVMConnectionUpdate,
			*message.LBVMConnectionFieldsUpdate,
			message.LBVMConnectionFieldsUpdate,
			*message.LBVMConnectionDelete,
			message.LBVMConnectionDelete,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeLBVMConnection),
			resourceType:    common.RESOURCE_TYPE_LB_VM_CONNECTION_EN,
		},
	}
}
