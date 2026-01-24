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
// 这个接口替代了原来复杂的泛型参数约束，提供了更简洁的消息创建方式
type MessageFactory interface {
	// CreateAddedMessage 创建资源批量添加消息
	CreateAddedMessage() types.Added

	// CreateUpdatedMessage 创建资源更新消息
	CreateUpdatedMessage() types.Updated

	// CreateDeletedMessage 创建资源批量删除消息
	CreateDeletedMessage() types.Deleted

	// CreateUpdatedFields 创建资源更新字段消息
	CreateUpdatedFields() types.UpdatedFields
}

// resourceMessageFactories 全局消息工厂注册表
// key: 资源类型名称 (如 "host", "vm", "network")
// value: 对应的消息工厂实例
var resourceMessageFactories = make(map[string]MessageFactory)

// RegisterMessageFactory 注册资源类型对应的消息工厂
func RegisterMessageFactory(resourceType string, factory MessageFactory) {
	resourceMessageFactories[resourceType] = factory
}

// GetMessageFactory 根据资源类型获取对应的消息工厂
func GetMessageFactory(resourceType string) MessageFactory {
	return resourceMessageFactories[resourceType]
}

// hasMessageFactory 检查是否已注册指定资源类型的消息工厂
func hasMessageFactory(resourceType string) bool {
	_, exists := resourceMessageFactories[resourceType]
	return exists
}
