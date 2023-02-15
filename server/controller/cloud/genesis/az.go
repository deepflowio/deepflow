/*
 * Copyright (c) 2022 Yunshan Networks
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

package genesis

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getAZ() (model.AZ, error) {
	log.Debug("get az starting")
	azLcuuid := common.GetUUID(common.DEFAULT_REGION_NAME, uuid.Nil)

	g.cloudStatsd.APICost["az"] = []int{0}
	g.cloudStatsd.APICount["az"] = []int{0}

	az := model.AZ{
		Lcuuid:       azLcuuid,
		RegionLcuuid: g.regionUuid,
		Name:         common.DEFAULT_REGION_NAME,
	}
	g.azLcuuid = azLcuuid
	log.Debug("get az complete")
	return az, nil
}
