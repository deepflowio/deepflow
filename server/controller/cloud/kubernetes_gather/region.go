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

package kubernetes_gather

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (k *KubernetesGather) getRegion() (model.Region, error) {
	log.Debug("get region starting")
	var region model.Region
	if k.RegionUuid == "" {
		k.RegionUuid = common.DEFAULT_REGION
		region = model.Region{
			Lcuuid: common.DEFAULT_REGION,
			Name:   common.DEFAULT_REGION_NAME,
		}
	}
	log.Debug("get region complete")
	return region, nil
}
