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

package genesis

import (
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (g *Genesis) getVinterfaces() ([]model.VInterface, error) {
	log.Debug("get vinterfaces starting", logger.NewORGPrefix(g.orgID))
	vinterfaces := []model.VInterface{}
	vinterfacesData := g.genesisData.Ports

	g.cloudStatsd.RefreshAPIMoniter("vinterfaces", len(vinterfacesData), time.Time{})

	for _, v := range vinterfacesData {
		if v.DeviceLcuuid == "" || v.NetworkLcuuid == "" {
			log.Debug("device lcuuid or network lcuuid not found", logger.NewORGPrefix(g.orgID))
			continue
		}
		vinterface := model.VInterface{
			Lcuuid:        v.Lcuuid,
			Type:          int(v.Type),
			Mac:           v.Mac,
			VPCLcuuid:     v.VPCLcuuid,
			RegionLcuuid:  g.regionLcuuid,
			DeviceType:    int(v.DeviceType),
			DeviceLcuuid:  v.DeviceLcuuid,
			NetworkLcuuid: v.NetworkLcuuid,
		}
		vinterfaces = append(vinterfaces, vinterface)
	}
	log.Debug("get vinterfaces complete", logger.NewORGPrefix(g.orgID))
	return vinterfaces, nil
}
