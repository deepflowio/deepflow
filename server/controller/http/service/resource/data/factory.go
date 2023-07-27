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

package data

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	mysqldp "github.com/deepflowio/deepflow/server/controller/http/service/resource/data/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	redisdp "github.com/deepflowio/deepflow/server/controller/http/service/resource/data/redis"
)

// GetDataProvider determines which resource uses which type of data provider
func GetDataProvider(resourceType string, redisCfg redis.Config) provider.DataProvider {
	switch resourceType {
	case common.RESOURCE_TYPE_AZ_EN:
		return mysqldp.NewAZ()
	case common.RESOURCE_TYPE_HOST_EN:
		return mysqldp.NewHost()
	case common.RESOURCE_TYPE_VM_EN:
		return redisdp.GetVM(redisCfg)
	case common.RESOURCE_TYPE_VINTERFACE_EN:
		return redisdp.GetVInterface(redisCfg)
	case common.RESOURCE_TYPE_POD_EN:
		return redisdp.GetPod(redisCfg)
	default:
		return nil
	}
}
