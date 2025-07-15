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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/vtap"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type ChVTap struct {
	UpdaterComponent[mysqlmodel.ChVTap, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVTap(resourceTypeToIconID map[IconKey]int) *ChVTap {
	updater := &ChVTap{
		newUpdaterComponent[mysqlmodel.ChVTap, IDKey](
			RESOURCE_TYPE_CH_VTAP,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}
func (v *ChVTap) generateNewData(db *mysql.DB) (map[IDKey]mysqlmodel.ChVTap, bool) {
	var vTaps []mysqlmodel.VTap
	err := db.Unscoped().Select("id", "type", "team_id", "name").Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	vtapVIFs, err := getVTapResource(db.ORGID)
	vTapIDToResourceID := map[int][3]int{}
	vTapIDToResourceName := map[int][3]string{}
	if err != nil {
		log.Warning("unable to get resource vtap-port", db.LogPrefixORGID)
	}
	for _, data := range vtapVIFs {
		vTapID := data.VTapID
		hostID := data.DeviceHostID
		chostID := data.DeviceCHostID
		podNodeID := data.DevicePodNodeID
		hostName := data.DeviceHostName
		chostName := data.DeviceCHostName
		podNodeName := data.DevicePodNodeName
		resourceID := [3]int{}
		resourceID[0], resourceID[1], resourceID[2] = hostID, chostID, podNodeID
		vTapIDToResourceID[vTapID] = resourceID
		resourceName := [3]string{}
		resourceName[0], resourceName[1], resourceName[2] = hostName, chostName, podNodeName
		vTapIDToResourceName[vTapID] = resourceName
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChVTap)
	for _, vTap := range vTaps {
		keyToItem[IDKey{ID: vTap.ID}] = mysqlmodel.ChVTap{
			ID:          vTap.ID,
			Name:        vTap.Name,
			Type:        vTap.Type,
			TeamID:      vTap.TeamID,
			HostID:      vTapIDToResourceID[vTap.ID][0],
			HostName:    vTapIDToResourceName[vTap.ID][0],
			CHostID:     vTapIDToResourceID[vTap.ID][1],
			CHostName:   vTapIDToResourceName[vTap.ID][1],
			PodNodeID:   vTapIDToResourceID[vTap.ID][2],
			PodNodeName: vTapIDToResourceName[vTap.ID][2],
		}
	}
	return keyToItem, true
}

func (v *ChVTap) generateKey(dbItem mysqlmodel.ChVTap) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (v *ChVTap) generateUpdateInfo(oldItem, newItem mysqlmodel.ChVTap) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.Type != newItem.Type {
		updateInfo["type"] = newItem.Type
	}
	if oldItem.HostID != newItem.HostID {
		updateInfo["host_id"] = newItem.HostID
	}
	if oldItem.HostName != newItem.HostName {
		updateInfo["host_name"] = newItem.HostName
	}
	if oldItem.CHostID != newItem.CHostID {
		updateInfo["chost_id"] = newItem.CHostID
	}
	if oldItem.CHostName != newItem.CHostName {
		updateInfo["chost_name"] = newItem.CHostName
	}
	if oldItem.PodNodeID != newItem.PodNodeID {
		updateInfo["pod_node_id"] = newItem.PodNodeID
	}
	if oldItem.PodNodeName != newItem.PodNodeName {
		updateInfo["pod_node_name"] = newItem.PodNodeName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func getVTapResource(orgID int) (resp []model.VTapInterface, err error) {
	return vtap.NewVTapInterface(
		common.FPermit{},
		httpcommon.NewUserInfo(common.USER_TYPE_SUPER_ADMIN, common.USER_ID_SUPER_ADMIN, orgID),
	).GetVIFResource(map[string]interface{}{})
}
