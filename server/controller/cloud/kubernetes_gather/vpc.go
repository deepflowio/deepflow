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

package kubernetes_gather

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getVPC() (model.VPC, error) {
	log.Debug("get vpc starting", logger.NewORGPrefix(k.orgID))
	if k.VPCUUID == "" {
		k.VPCUUID = common.GetVPCLcuuidFromUUIDGenerate(k.orgID, k.UuidGenerate)
	}
	vpc := model.VPC{
		Lcuuid:       k.VPCUUID,
		Name:         k.Name,
		RegionLcuuid: k.RegionUUID,
	}
	log.Debug("get vpc complete", logger.NewORGPrefix(k.orgID))
	return vpc, nil
}
