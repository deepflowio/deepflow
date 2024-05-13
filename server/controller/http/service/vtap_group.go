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

package service

import (
	"fmt"
	"regexp"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

const VTAP_GROUP_SHORT_UUID_PREFIX = "g-"

var vtapGroupShortUUIDRegexp, _ = regexp.Compile(`^g-[A-Za-z0-9]{10}$`)

type AgentGroup struct {
	cfg *config.ControllerConfig

	userInfo *UserInfo
}

func NewAgentGroup(userInfo *UserInfo, cfg *config.ControllerConfig) *AgentGroup {
	return &AgentGroup{userInfo: userInfo, cfg: cfg}
}

func (a *AgentGroup) Get(filter map[string]interface{}) (resp []model.VtapGroup, err error) {
	var response []model.VtapGroup
	var allVTaps []mysql.VTap
	var allVTapGroups []*mysql.VTapGroup
	var vtapGroupLcuuids []string
	var groupToVtapLcuuids map[string][]string
	var groupToPendingVtapLcuuids map[string][]string
	var groupToDisableVtapLcuuids map[string][]string

	dbInfo, err := mysql.GetDB(a.userInfo.ORGID)
	if err != nil {
		return nil, err
	}
	Db, vtapDB := dbInfo.DB, dbInfo.DB
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["name"]; ok {
		Db = Db.Where("name = ?", filter["name"])
	}
	if _, ok := filter["short_uuid"]; ok {
		Db = Db.Where("short_uuid = ?", filter["short_uuid"])
	}
	if _, ok := filter["team_id"]; ok {
		Db = Db.Where("team_id = ?", filter["team_id"])
	}
	Db.Order("created_at DESC").Find(&allVTapGroups)
	vtapGroups, err := getAgentGroupByUser(a.userInfo, &a.cfg.FPermit, allVTapGroups)
	if err != nil {
		return nil, err
	}

	for _, vtapGroup := range vtapGroups {
		vtapGroupLcuuids = append(vtapGroupLcuuids, vtapGroup.Lcuuid)
	}
	vtapDB.Where("vtap_group_lcuuid IN (?)", vtapGroupLcuuids).Find(&allVTaps)
	vtaps, err := getAgentByUser(a.userInfo, &a.cfg.FPermit, allVTaps)
	if err != nil {
		return nil, err
	}

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
			TeamID:             vtapGroup.TeamID,
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

func (a *AgentGroup) Create(vtapGroupCreate model.VtapGroupCreate) (resp model.VtapGroup, err error) {
	if err := IsAddPermitted(a.cfg.FPermit, a.userInfo, vtapGroupCreate.TeamID); err != nil {
		return model.VtapGroup{}, err
	}

	cfg := a.cfg
	var vtapGroupCount int64

	dbInfo, err := mysql.GetDB(a.userInfo.ORGID)
	if err != nil {
		return model.VtapGroup{}, err
	}
	db := dbInfo.DB
	db.Model(&mysql.VTapGroup{}).Where("name = ?", vtapGroupCreate.Name).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return model.VtapGroup{}, NewError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("vtap_group (%s) already exist", vtapGroupCreate.Name))
	}

	db.Model(&mysql.VTapGroup{}).Count(&vtapGroupCount)
	if int(vtapGroupCount) > cfg.Spec.VTapGroupMax {
		return model.VtapGroup{}, NewError(
			httpcommon.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("vtap_group count exceeds (limit %d)", cfg.Spec.VTapGroupMax),
		)
	}

	if len(vtapGroupCreate.VtapLcuuids) > cfg.Spec.VTapMaxPerGroup {
		return model.VtapGroup{}, NewError(
			httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED,
			fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
		)
	}

	shortUUID := VTAP_GROUP_SHORT_UUID_PREFIX + common.GenerateShortUUID()
	groupID := vtapGroupCreate.GroupID
	// verify vtap group id in deepflow-ctl command model
	if err := verifyGroupID(db, groupID); err != nil {
		return model.VtapGroup{}, NewError(httpcommon.INVALID_POST_DATA, err.Error())
	}
	if groupID != "" {
		shortUUID = groupID
	}

	vtapGroup := mysql.VTapGroup{}
	lcuuid := uuid.New().String()
	vtapGroup.Lcuuid = lcuuid
	vtapGroup.ShortUUID = shortUUID
	vtapGroup.Name = vtapGroupCreate.Name
	vtapGroup.TeamID = vtapGroupCreate.TeamID
	db.Create(&vtapGroup)

	var allVTaps []mysql.VTap
	db.Where("lcuuid IN (?)", vtapGroupCreate.VtapLcuuids).Find(&allVTaps)
	vtaps, err := getAgentByUser(a.userInfo, &a.cfg.FPermit, allVTaps)
	if err != nil {
		return model.VtapGroup{}, err
	}
	for _, vtap := range vtaps {
		db.Model(&vtap).Updates(map[string]interface{}{"vtap_group_lcuuid": lcuuid, "team_id": vtapGroupCreate.TeamID})
	}

	response, _ := a.Get(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache(a.userInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return response[0], nil
}

// IsVtapGroupShortUUID checks uuid consists of numbers and English letters with g- prefix.
func IsVtapGroupShortUUID(uuid string) bool {
	result := vtapGroupShortUUIDRegexp.FindAllStringSubmatch(uuid, -1)
	return len(result) != 0
}

func verifyGroupID(db *gorm.DB, groupID string) error {
	if groupID == "" {
		return nil
	}
	if !IsVtapGroupShortUUID(groupID) {
		return NewError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("id(%s) invalid, requires %s prefix, number and letter length %d, such as g-1yhIguXABC",
				groupID, VTAP_GROUP_SHORT_UUID_PREFIX, common.SHORT_UUID_LENGTH),
		)
	}

	var vtapGroupCount int64
	db.Model(&mysql.VTapGroup{}).Where("short_uuid = ?", groupID).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return NewError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("id(%s) already exist", groupID))
	}
	return nil
}

func (a *AgentGroup) Update(lcuuid string, vtapGroupUpdate map[string]interface{}, cfg *config.ControllerConfig) (resp model.VtapGroup, err error) {
	dbInfo, err := mysql.GetDB(a.userInfo.ORGID)
	if err != nil {
		return model.VtapGroup{}, err
	}
	db := dbInfo.DB

	var vtapGroup mysql.VTapGroup
	var dbUpdateMap = make(map[string]interface{})
	if ret := db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return model.VtapGroup{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}
	if err := IsUpdatePermitted(a.cfg.FPermit, a.userInfo, vtapGroup.TeamID); err != nil {
		return model.VtapGroup{}, err
	}

	log.Infof("ORG(id=%d database=%s) update vtap_group (%s) config %v", dbInfo.ORGID, dbInfo.Name, vtapGroup.Name, vtapGroupUpdate)

	// 修改名称
	if _, ok := vtapGroupUpdate["NAME"]; ok {
		dbUpdateMap["name"] = vtapGroupUpdate["NAME"]
	}

	// 修改状态
	if _, ok := vtapGroupUpdate["STATE"]; ok {
		db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("state", vtapGroupUpdate["STATE"])
	}

	// 注册采集器
	if _, ok := vtapGroupUpdate["ENABLE"]; ok {
		db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("enable", vtapGroupUpdate["ENABLE"])
	}

	if _, ok := vtapGroupUpdate["TEAM_ID"]; ok {
		dbUpdateMap["team_id"] = vtapGroupUpdate["TEAM_ID"]
		// update vtap team id
		var vtaps []mysql.VTap
		db.Where("vtap_group_lcuuid IN (?)", vtapGroup.Lcuuid).Find(&vtaps)
		for _, vtap := range vtaps {
			log.Infof("ORG(id=%d database=%s) update team(%v -> %v)",
				dbInfo.ORGID, dbInfo.Name, vtap.TeamID, dbUpdateMap["team_id"])
			db.Model(vtap).Update("team_id", dbUpdateMap["team_id"])
		}
	}

	// 修改组内采集器
	if _, ok := vtapGroupUpdate["VTAP_LCUUIDS"]; ok {
		if len(vtapGroupUpdate["VTAP_LCUUIDS"].([]interface{})) > cfg.Spec.VTapMaxPerGroup {
			return model.VtapGroup{}, NewError(
				httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED,
				fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
			)
		}

		var allOldVtaps []mysql.VTap
		var allNewVtaps []mysql.VTap
		db.Where("vtap_group_lcuuid IN (?)", vtapGroup.Lcuuid).Find(&allOldVtaps)
		oldVtaps, err := getAgentByUser(a.userInfo, &a.cfg.FPermit, allOldVtaps)
		if err != nil {
			return model.VtapGroup{}, err
		}
		db.Where("lcuuid IN (?)", vtapGroupUpdate["VTAP_LCUUIDS"]).Find(&allNewVtaps)
		newVtaps, err := getAgentByUser(a.userInfo, &a.cfg.FPermit, allNewVtaps)
		if err != nil {
			return model.VtapGroup{}, err
		}

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
		if ret := db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
			return model.VtapGroup{}, NewError(httpcommon.RESOURCE_NOT_FOUND, "default vtap_group not found")
		}

		for _, lcuuid := range delVtapLcuuids.ToSlice() {
			vtap := lcuuidToOldVtap[lcuuid.(string)]
			log.Infof("ORG(id=%d database=%s) update vtap group lcuuid(%s -> %s), team(%v -> %v)",
				dbInfo.ORGID, dbInfo.Name, vtap.VtapGroupLcuuid, defaultVtapGroup.Lcuuid, vtapGroup.TeamID, common.DEFAULT_TEAM_ID)
			db.Model(vtap).Updates(map[string]interface{}{"vtap_group_lcuuid": defaultVtapGroup.Lcuuid, "team_id": common.DEFAULT_TEAM_ID})
		}

		teamID := dbUpdateMap["team_id"]
		if teamID == "" {
			teamID = vtapGroup.TeamID
		}
		for _, lcuuid := range addVtapLcuuids.ToSlice() {
			vtap := lcuuidToNewVtap[lcuuid.(string)]
			log.Infof("ORG(id=%d database=%s) update vtap group lcuuid(%s - > %s), team(%v -> %v)",
				dbInfo.ORGID, dbInfo.Name, vtap.VtapGroupLcuuid, vtapGroup.Lcuuid, vtapGroup.TeamID, teamID)
			db.Model(vtap).Updates(map[string]interface{}{"vtap_group_lcuuid": vtapGroup.Lcuuid, "team_id": teamID})
		}
	}

	// 更新vtap_group DB
	db.Model(&vtapGroup).Updates(dbUpdateMap)

	response, _ := a.Get(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache(a.userInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return response[0], nil
}

func (a *AgentGroup) Delete(lcuuid string) (resp map[string]string, err error) {
	dbInfo, err := mysql.GetDB(a.userInfo.ORGID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB

	var vtapGroup mysql.VTapGroup
	if ret := db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return map[string]string{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}
	if err := IsDeletePermitted(a.cfg.FPermit, a.userInfo, vtapGroup.TeamID); err != nil {
		return nil, err
	}

	var defaultVtapGroup mysql.VTapGroup
	if ret := db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
		return map[string]string{}, NewError(httpcommon.RESOURCE_NOT_FOUND, "default vtap_group not found")
	}

	log.Infof("ORG(id=%d database=%s) delete vtap_group (%s)", dbInfo.ORGID, dbInfo.Name, vtapGroup.Name)

	db.Model(&mysql.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).
		Updates(map[string]interface{}{"vtap_group_lcuuid": defaultVtapGroup.Lcuuid, "team_id": defaultVtapGroup.TeamID})
	db.Delete(&vtapGroup)
	db.Where("vtap_group_lcuuid = ?", lcuuid).Delete(&agent_config.AgentGroupConfigModel{})
	refresh.RefreshCache(a.userInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return map[string]string{"LCUUID": lcuuid}, nil
}
