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

package redis

import (
	"sync"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	mysqldp "github.com/deepflowio/deepflow/server/controller/http/service/resource/data/mysql"
)

var (
	vmOnce sync.Once
	vm     *VM
)

type VM struct {
	DataProvider
}

func GetVM(cfg redis.Config) *VM {
	vmOnce.Do(func() {
		vm = &VM{
			DataProvider: DataProvider{
				resourceType: ctrlcommon.RESOURCE_TYPE_VM_EN,
				next:         mysqldp.NewVM(),
				client:       getClient(cfg),
				keyConv:      newKeyConvertor[model.VMQueryStoredInRedis](),
				urlPath:      httpcommon.PATH_VM,
			},
		}
	})
	return vm
}
