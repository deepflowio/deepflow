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

package updater

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// MessageFactory 为不同资源类型创建对应的消息实例
type MessageFactory interface {
	CreateAddedMessage() types.Added
	CreateUpdatedMessage() types.Updated
	CreateDeletedMessage() types.Deleted
	CreateUpdatedFields() types.UpdatedFields
}

// resourceMessageFactories 全局消息工厂注册表，各资源类型通过 init() 函数注册
// key: 资源类型名称 (如 "host", "vm", "network")
// value: 对应的消息工厂实例
var resourceMessageFactories = make(map[string]MessageFactory)

// RegisterMessageFactory 注册资源类型对应的消息工厂，由各资源文件的 init() 调用
func RegisterMessageFactory(resourceType string, factory MessageFactory) {
	resourceMessageFactories[resourceType] = factory
}

// GetMessageFactory 根据资源类型获取对应的消息工厂
func GetMessageFactory(resourceType string) MessageFactory {
	return resourceMessageFactories[resourceType]
}
