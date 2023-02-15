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

package service

import (
	"fmt"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

const VTAP_GROUP_SHORT_UUID_PREFIX = "g-"

func GetVtapGroups(filter map[string]interface{}) (resp []model.VtapGroup, err error) {
	var response []model.VtapGroup
	var vtaps []mysql.VTap
	var vtapGroups []mysql.VTapGroup
	var vtapGroupLcuuids []string
	var groupToVtapLcuuids map[string][]string
	var groupToPendingVtapLcuuids map[string][]string
	var groupToDisableVtapLcuuids map[string][]string

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["name"]; ok {
		Db = Db.Where("name = ?", filter["name"])
	}
	if _, ok := filter["short_uuid"]; ok {
		Db = Db.Where("short_uuid = ?", filter["short_uuid"])
	}
	Db.Order("created_at DESC").Find(&vtapGroups)

	for _, vtapGroup := range vtapGroups {
		vtapGroupLcuuids = append(vtapGroupLcuuids, vtapGroup.Lcuuid)
	}
	mysql.Db.Where("vtap_group_lcuuid IN (?)", vtapGroupLcuuids).Find(&vtaps)

	groupToVtapLcuuids = make(map[string][]string)
	groupToPendingVtapLcuuids = make(map[string][]string)
	groupToDisableVtapLcuuids = make(map[string][]string)
	for _, vtap := range vtaps {
		groupToVtapLcuuids[vtap.VtapGroupLcuuid] = append(groupToVtapLcuuids[vtap.VtapGroupLcuuid], vtap.Lcuuid)
		if vtap.State == common.VTAP_STATE_PENDING {
			groupToPendingVtapLcuuids[vtap.VtapGroupLcuuid] = append(
				groupToPendingVtapLcuuids[vtap.VtapGroupLcuuid], vtap.Lcuuid)
		} else if vtap.Enable == common.VTAP_ENABLE_FALSE {
			groupToDisableVtapLcuuids[vtap.VtapGroupLcuuid] = append(
				groupToDisableVtapLcuuids[vtap.VtapGroupLcuuid], vtap.Lcuuid)
		}
	}

	for _, vtapGroup := range vtapGroups {
		vtapGroupResp := model.VtapGroup{
			ID:                 vtapGroup.ID,
			Name:               vtapGroup.Name,
			ShortUUID:          vtapGroup.ShortUUID,
			Lcuuid:             vtapGroup.Lcuuid,
			UpdatedAt:          vtapGroup.UpdatedAt.Format(common.GO_BIRTHDAY),
			VtapLcuuids:        []string{},
			PendingVtapLcuuids: []string{},
			DisableVtapLcuuids: []string{},
		}

		if _, ok := groupToVtapLcuuids[vtapGroup.Lcuuid]; ok {
			vtapGroupResp.VtapLcuuids = groupToVtapLcuuids[vtapGroup.Lcuuid]
		}
		if _, ok := groupToPendingVtapLcuuids[vtapGroup.Lcuuid]; ok {
			vtapGroupResp.PendingVtapLcuuids = groupToPendingVtapLcuuids[vtapGroup.Lcuuid]
		}
		if _, ok := groupToDisableVtapLcuuids[vtapGroup.Lcuuid]; ok {
			vtapGroupResp.DisableVtapLcuuids = groupToDisableVtapLcuuids[vtapGroup.Lcuuid]
		}

		if vtapGroup.ID == common.DEFAULT_VTAP_GROUP_ID {
			response = append([]model.VtapGroup{vtapGroupResp}, response[0:]...)
		} else {
			response = append(response, vtapGroupResp)
		}
	}
	return response, nil
}

func CreateVtapGroup(vtapGroupCreate model.VtapGroupCreate, cfg *config.ControllerConfig) (resp model.VtapGroup, err error) {
	var vtapGroupCount int64

	mysql.Db.Model(&mysql.VTapGroup{}).Where("name = ?", vtapGroupCreate.Name).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return model.VtapGroup{}, NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("vtap_group (%s) already exist", vtapGroupCreate.Name))
	}

	mysql.Db.Model(&mysql.VTapGroup{}).Count(&vtapGroupCount)
	if int(vtapGroupCount) > cfg.Spec.VTapGroupMax {
		return model.VtapGroup{}, NewError(
			common.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("vtap_group count exceeds (limit %d)", cfg.Spec.VTapGroupMax),
		)
	}

	if len(vtapGroupCreate.VtapLcuuids) > cfg.Spec.VTapMaxPerGroup {
		return model.VtapGroup{}, NewError(
			common.SELECTED_RESOURCES_NUM_EXCEEDED,
			fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
		)
	}

	shortUUID := VTAP_GROUP_SHORT_UUID_PREFIX + common.GenerateShortUUID()
	groupID := vtapGroupCreate.GroupID
	// verify vtap group id in deepflow-ctl command model
	if err := verifyGroupID(groupID); err != nil {
		return model.VtapGroup{}, NewError(common.INVALID_POST_DATA, err.Error())
	}
	if groupID != "" {
		shortUUID = groupID
	}

	vtapGroup := mysql.VTapGroup{}
	lcuuid := uuid.New().String()
	vtapGroup.Lcuuid = lcuuid
	vtapGroup.ShortUUID = shortUUID
	vtapGroup.Name = vtapGroupCreate.Name
	mysql.Db.Create(&vtapGroup)

	var vtaps []mysql.VTap
	mysql.Db.Where("lcuuid IN (?)", vtapGroupCreate.VtapLcuuids).Find(&vtaps)
	for _, vtap := range vtaps {
		mysql.Db.Model(&vtap).Update("vtap_group_lcuuid", lcuuid)
	}

	response, _ := GetVtapGroups(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache([]string{common.VTAP_CHANGED})
	return response[0], nil
}

func verifyGroupID(groupID string) error {
	if groupID == "" {
		return nil
	}
	if !common.IsVtapGroupShortUUID(groupID) {
		return NewError(
			common.INVALID_POST_DATA,
			fmt.Sprintf("id(%s) invalid, requires %s prefix, number and letter length %d, such as g-1yhIguXABC",
				groupID, VTAP_GROUP_SHORT_UUID_PREFIX, common.SHORT_UUID_LENGTH),
		)
	}

	var vtapGroupCount int64
	mysql.Db.Model(&mysql.VTapGroup{}).Where("short_uuid = ?", groupID).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return NewError(common.RESOURCE_ALREADY_EXIST, fmt.Sprintf("id(%s) already exist", groupID))
	}
	return nil
}

func UpdateVtapGroup(lcuuid string, vtapGroupUpdate map[string]interface{}, cfg *config.ControllerConfig) (resp model.VtapGroup, err error) {
	var vtapGroup mysql.VTapGroup
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return model.VtapGroup{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}

	log.Infof("update vtap_group (%s) config %v", vtapGroup.Name, vtapGroupUpdate)

	// 修改名称
	if _, ok := vtapGroupUpdate["NAME"]; ok {
		dbUpdateMap["name"] = vtapGroupUpdate["NAME"]
	}

	// 修改状态
	if _, ok := vtapGroupUpdate["STATE"]; ok {
		mysql.Db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("state", vtapGroupUpdate["STATE"])
	}

	// 注册采集器
	if _, ok := vtapGroupUpdate["ENABLE"]; ok {
		mysql.Db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("enable", vtapGroupUpdate["ENABLE"])
	}

	// 修改组内采集器
	if _, ok := vtapGroupUpdate["VTAP_LCUUIDS"]; ok {
		if len(vtapGroupUpdate["VTAP_LCUUIDS"].([]interface{})) > cfg.Spec.VTapMaxPerGroup {
			return model.VtapGroup{}, NewError(
				common.SELECTED_RESOURCES_NUM_EXCEEDED,
				fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
			)
		}

		var oldVtaps []mysql.VTap
		var newVtaps []mysql.VTap
		mysql.Db.Where("vtap_group_lcuuid IN (?)", vtapGroup.Lcuuid).Find(&oldVtaps)
		mysql.Db.Where("lcuuid IN (?)", vtapGroupUpdate["VTAP_LCUUIDS"]).Find(&newVtaps)

		lcuuidToOldVtap := make(map[string]*mysql.VTap)
		lcuuidToNewVtap := make(map[string]*mysql.VTap)
		var oldVtapLcuuids = mapset.NewSet()
		var newVtapLcuuids = mapset.NewSet()
		var delVtapLcuuids = mapset.NewSet()
		var addVtapLcuuids = mapset.NewSet()
		for i, vtap := range oldVtaps {
			lcuuidToOldVtap[vtap.Lcuuid] = &oldVtaps[i]
			oldVtapLcuuids.Add(vtap.Lcuuid)
		}
		for i, vtap := range newVtaps {
			lcuuidToNewVtap[vtap.Lcuuid] = &newVtaps[i]
			newVtapLcuuids.Add(vtap.Lcuuid)
		}

		delVtapLcuuids = oldVtapLcuuids.Difference(newVtapLcuuids)
		addVtapLcuuids = newVtapLcuuids.Difference(oldVtapLcuuids)

		var defaultVtapGroup mysql.VTapGroup
		if ret := mysql.Db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
			return model.VtapGroup{}, NewError(common.RESOURCE_NOT_FOUND, "default vtap_group not found")
		}

		for _, lcuuid := range delVtapLcuuids.ToSlice() {
			vtap := lcuuidToOldVtap[lcuuid.(string)]
			// TODO：记录操作日志
			mysql.Db.Model(vtap).Update("vtap_group_lcuuid", defaultVtapGroup.Lcuuid)
		}

		for _, lcuuid := range addVtapLcuuids.ToSlice() {
			vtap := lcuuidToNewVtap[lcuuid.(string)]
			// TODO：记录操作日志
			mysql.Db.Model(vtap).Update("vtap_group_lcuuid", vtapGroup.Lcuuid)
		}
	}

	// 更新vtap_group DB
	mysql.Db.Model(&vtapGroup).Updates(dbUpdateMap)

	response, _ := GetVtapGroups(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache([]string{common.VTAP_CHANGED})
	return response[0], nil
}

func DeleteVtapGroup(lcuuid string) (resp map[string]string, err error) {
	var vtapGroup mysql.VTapGroup

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return map[string]string{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}

	var defaultVtapGroup mysql.VTapGroup
	if ret := mysql.Db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
		return map[string]string{}, NewError(common.RESOURCE_NOT_FOUND, "default vtap_group not found")
	}

	log.Infof("delete vtap_group (%s)", vtapGroup.Name)

	mysql.Db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("vtap_group_lcuuid", defaultVtapGroup.Lcuuid)
	mysql.Db.Delete(&vtapGroup)
	mysql.Db.Where("vtap_group_lcuuid = ?", lcuuid).Delete(&mysql.VTapGroupConfiguration{})
	refresh.RefreshCache([]string{common.VTAP_CHANGED})
	return map[string]string{"LCUUID": lcuuid}, nil
}
