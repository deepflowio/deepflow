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
	"reflect"
	"regexp"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/uuid"
	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service/agentlicense"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

const VTAP_GROUP_SHORT_UUID_PREFIX = "g-"

var vtapGroupShortUUIDRegexp, _ = regexp.Compile(`^g-[A-Za-z0-9]{10}$`)

type AgentGroup struct {
	cfg *config.ControllerConfig

	resourceAccess *ResourceAccess
}

func NewAgentGroup(userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) *AgentGroup {
	return &AgentGroup{
		cfg:            cfg,
		resourceAccess: &ResourceAccess{Fpermit: cfg.FPermit, UserInfo: userInfo},
	}
}

func (a *AgentGroup) Get(filter map[string]interface{}) (resp []model.VtapGroup, err error) {
	var response []model.VtapGroup
	var allVTaps []mysqlmodel.VTap
	var allVTapGroups []*mysqlmodel.VTapGroup
	var vtapGroupLcuuids []string
	var groupToVtapLcuuids map[string][]string
	var groupToPendingVtapLcuuids map[string][]string
	var groupToDisableVtapLcuuids map[string][]string

	userInfo := a.resourceAccess.UserInfo
	dbInfo, err := mysql.GetDB(userInfo.ORGID)
	if err != nil {
		return nil, err
	}
	Db, vtapDB := dbInfo.DB, dbInfo.DB
	for _, field := range []string{"lcuuid", "name", "short_uuid", "team_id", "user_id"} {
		if v, ok := filter[field]; ok {
			Db = Db.Where(fmt.Sprintf("%s = ?", field), v)
		}
	}
	Db.Order("created_at DESC").Find(&allVTapGroups)
	vtapGroups, err := GetAgentGroupByUser(userInfo, &a.cfg.FPermit, allVTapGroups)
	if err != nil {
		return nil, err
	}

	for _, vtapGroup := range vtapGroups {
		vtapGroupLcuuids = append(vtapGroupLcuuids, vtapGroup.Lcuuid)
	}
	vtapDB.Where("vtap_group_lcuuid IN (?)", vtapGroupLcuuids).Find(&allVTaps)
	vtaps, err := GetAgentByUser(userInfo, &a.cfg.FPermit, allVTaps)
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
		// Default agent group does not return.
		if _, ok := filter["can_deleted"]; ok && vtapGroup.ID == 1 {
			continue
		}

		vtapGroupResp := model.VtapGroup{
			ID:                 vtapGroup.ID,
			Name:               vtapGroup.Name,
			ShortUUID:          vtapGroup.ShortUUID,
			Lcuuid:             vtapGroup.Lcuuid,
			TeamID:             vtapGroup.TeamID,
			UserID:             vtapGroup.UserID,
			UpdatedAt:          vtapGroup.UpdatedAt.Format(common.GO_BIRTHDAY),
			VtapLcuuids:        []string{},
			PendingVtapLcuuids: []string{},
			DisableVtapLcuuids: []string{},
		}

		vtapGroupResp.LicenseFunctions, err = ConvertStrToIntList(vtapGroup.LicenseFunctions)
		if err != nil {
			return nil, err
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
	lcuuid := uuid.New().String()
	if err := a.resourceAccess.CanAddResource(vtapGroupCreate.TeamID, common.SET_RESOURCE_TYPE_AGENT_GROUP, lcuuid); err != nil {
		return model.VtapGroup{}, err
	}

	cfg := a.cfg
	var vtapGroupCount int64
	userInfo := a.resourceAccess.UserInfo
	dbInfo, err := mysql.GetDB(userInfo.ORGID)
	if err != nil {
		return model.VtapGroup{}, err
	}
	db := dbInfo.DB

	db.Model(&mysqlmodel.VTapGroup{}).Count(&vtapGroupCount)
	if int(vtapGroupCount) > cfg.Spec.VTapGroupMax {
		return model.VtapGroup{}, response.ServiceError(
			httpcommon.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("vtap_group count exceeds (limit %d)", cfg.Spec.VTapGroupMax),
		)
	}

	if len(vtapGroupCreate.VtapLcuuids) > cfg.Spec.VTapMaxPerGroup {
		return model.VtapGroup{}, response.ServiceError(
			httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED,
			fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
		)
	}

	var allVTaps []mysqlmodel.VTap
	if err = db.Where("lcuuid IN (?)", vtapGroupCreate.VtapLcuuids).Find(&allVTaps).Error; err != nil {
		return model.VtapGroup{}, err
	}
	vtaps, err := GetAgentByUser(userInfo, &a.cfg.FPermit, allVTaps)
	if err != nil {
		return model.VtapGroup{}, err
	}
	for _, vtap := range vtaps {
		if vtap.TeamID != vtapGroupCreate.TeamID {
			return model.VtapGroup{}, fmt.Errorf("agent team(%d) must equal to agent group team(%d)", vtap.TeamID, vtapGroupCreate.TeamID)
		}
	}

	shortUUID := VTAP_GROUP_SHORT_UUID_PREFIX + common.GenerateShortUUID()
	groupID := vtapGroupCreate.GroupID
	// verify vtap group id in deepflow-ctl command model
	if err := verifyGroupID(db, groupID); err != nil {
		return model.VtapGroup{}, response.ServiceError(httpcommon.INVALID_POST_DATA, err.Error())
	}
	if groupID != "" {
		shortUUID = groupID
	}

	vtapGroup := mysqlmodel.VTapGroup{}
	vtapGroup.Lcuuid = lcuuid
	vtapGroup.ShortUUID = shortUUID
	vtapGroup.Name = vtapGroupCreate.Name
	vtapGroup.TeamID = vtapGroupCreate.TeamID
	vtapGroup.UserID = a.resourceAccess.UserInfo.ID
	vtapGroup.LicenseFunctions = common.VTAP_ALL_LICENSE_FUNCTIONS

	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&vtapGroup).Error; err != nil {
			return err
		}
		for _, vtap := range vtaps {
			if err := tx.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Updates(map[string]interface{}{"vtap_group_lcuuid": lcuuid,
				"team_id": vtapGroupCreate.TeamID}).Error; err != nil {
				return err
			}
		}

		return agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, &vtapGroup, vtaps)
	})
	if err != nil {
		return model.VtapGroup{}, err
	}

	response, _ := a.Get(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache(userInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
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
		return response.ServiceError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("id(%s) invalid, requires %s prefix, number and letter length %d, such as g-1yhIguXABC",
				groupID, VTAP_GROUP_SHORT_UUID_PREFIX, common.SHORT_UUID_LENGTH),
		)
	}

	var vtapGroupCount int64
	db.Model(&mysqlmodel.VTapGroup{}).Where("short_uuid = ?", groupID).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("id(%s) already exist", groupID))
	}
	return nil
}

func (a *AgentGroup) Update(lcuuid string, vtapGroupUpdate map[string]interface{}, cfg *config.ControllerConfig) (resp model.VtapGroup, err error) {
	userInfo := a.resourceAccess.UserInfo
	dbInfo, err := mysql.GetDB(userInfo.ORGID)
	if err != nil {
		return model.VtapGroup{}, err
	}

	db := dbInfo.DB
	err = db.Transaction(func(tx *gorm.DB) error {
		var vtapGroup mysqlmodel.VTapGroup
		var vtapGroupTeamID int
		if ret := tx.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
			return fmt.Errorf("vtap_group (%s) not found", lcuuid)
		}
		vtapGroupTeamID = vtapGroup.TeamID
		resourceUpdate := map[string]interface{}{
			"team_id":       vtapGroupUpdate["TEAM_ID"],
			"owner_user_id": vtapGroupUpdate["USER_ID"],
		}
		if _, ok := vtapGroupUpdate["USER_ID"]; !ok {
			resourceUpdate = nil
		}
		if err := a.resourceAccess.CanUpdateResource(vtapGroup.TeamID,
			common.SET_RESOURCE_TYPE_AGENT_GROUP, vtapGroup.Lcuuid, resourceUpdate); err != nil {
			return err
		}
		var vtapGroupConfigs []agentconf.AgentGroupConfigModel
		db.Where("vtap_group_lcuuid = ?", lcuuid).Find(&vtapGroupConfigs)
		// transfer agent group config
		_, ok1 := vtapGroupUpdate["TEAM_ID"]
		_, ok2 := vtapGroupUpdate["USER_ID"]
		if ok1 && ok2 {
			for _, vtapGroupConfig := range vtapGroupConfigs {
				if err := a.resourceAccess.CanUpdateResource(vtapGroup.TeamID,
					common.SET_RESOURCE_TYPE_AGENT_GROUP_CONFIG, *vtapGroupConfig.Lcuuid, resourceUpdate); err != nil {
					return err
				}
			}
		}

		log.Infof("update vtap_group (%s) config %v", vtapGroup.Name, vtapGroupUpdate, dbInfo.LogPrefixORGID, dbInfo.LogPrefixName)

		var dbUpdateMap = make(map[string]interface{})
		// 修改名称
		if _, ok := vtapGroupUpdate["NAME"]; ok {
			dbUpdateMap["name"] = vtapGroupUpdate["NAME"]
		}

		// 修改状态
		if _, ok := vtapGroupUpdate["STATE"]; ok {
			tx.Model(&mysqlmodel.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("state", vtapGroupUpdate["STATE"])
		}

		// 注册采集器
		if _, ok := vtapGroupUpdate["ENABLE"]; ok {
			tx.Model(&mysqlmodel.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Update("enable", vtapGroupUpdate["ENABLE"])
		}

		if _, ok := vtapGroupUpdate["TEAM_ID"]; ok {
			dbUpdateMap["team_id"] = vtapGroupUpdate["TEAM_ID"]
			vtapGroupTeamIDFloat, ok := vtapGroupUpdate["TEAM_ID"].(float64)
			if !ok {
				return fmt.Errorf("get team id(type=%s) error", reflect.TypeOf(vtapGroupUpdate["TEAM_ID"]).String())
			}
			vtapGroupTeamID = int(vtapGroupTeamIDFloat)
		}
		if _, ok := vtapGroupUpdate["USER_ID"]; ok {
			dbUpdateMap["user_id"] = vtapGroupUpdate["USER_ID"]
		}

		var allOldVtaps []mysqlmodel.VTap
		tx.Where("vtap_group_lcuuid IN (?)", vtapGroup.Lcuuid).Find(&allOldVtaps)
		oldVtaps, err := GetAgentByUser(userInfo, &a.cfg.FPermit, allOldVtaps)
		if err != nil {
			return err
		}

		if _, ok := vtapGroupUpdate["ENABLE"]; ok {
			for _, vtap := range allOldVtaps {
				if err := a.resourceAccess.CanUpdateResource(vtap.TeamID,
					common.SET_RESOURCE_TYPE_AGENT, vtap.Lcuuid, nil); err != nil {
					return fmt.Errorf("%w no permission to update agent(%s)", err, vtap.Name)
				}
			}
		}

		// update agents in agent group
		if _, ok := vtapGroupUpdate["VTAP_LCUUIDS"]; ok {
			if len(vtapGroupUpdate["VTAP_LCUUIDS"].([]interface{})) > cfg.Spec.VTapMaxPerGroup {
				return response.ServiceError(
					httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED,
					fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
				)
			}

			var allNewVtaps []mysqlmodel.VTap
			tx.Where("lcuuid IN (?)", vtapGroupUpdate["VTAP_LCUUIDS"]).Find(&allNewVtaps)
			newVtaps, err := GetAgentByUser(userInfo, &a.cfg.FPermit, allNewVtaps)
			if err != nil {
				return err
			}

			lcuuidToOldVtap := make(map[string]*mysqlmodel.VTap)
			lcuuidToNewVtap := make(map[string]*mysqlmodel.VTap)
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

			var defaultVtapGroup mysqlmodel.VTapGroup
			if ret := tx.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
				return response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, "default vtap_group not found")
			}

			var agents []mysqlmodel.VTap
			for _, lcuuid := range delVtapLcuuids.ToSlice() {
				vtap := lcuuidToOldVtap[lcuuid.(string)]
				log.Infof("update vtap group lcuuid(%s -> %s)",
					vtap.VtapGroupLcuuid, defaultVtapGroup.Lcuuid, dbInfo.LogPrefixORGID, dbInfo.LogPrefixName)
				if err = tx.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Updates(map[string]interface{}{"vtap_group_lcuuid": defaultVtapGroup.Lcuuid}).Error; err != nil {
					return err
				}
				agents = append(agents, *vtap)
			}
			if len(agents) > 0 {
				if err := agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, &defaultVtapGroup, agents); err != nil {
					return err
				}
			}

			agents = []mysqlmodel.VTap{}
			for _, lcuuid := range addVtapLcuuids.ToSlice() {
				vtap := lcuuidToNewVtap[lcuuid.(string)]
				if vtap.TeamID != vtapGroupTeamID {
					return fmt.Errorf(
						"agent(%s) team(%d) must equal to agent group team(%d)", vtap.Name, vtap.TeamID, vtapGroupTeamID)
				}
				log.Infof("update vtap group lcuuid(%s - > %s)",
					vtap.VtapGroupLcuuid, vtapGroup.Lcuuid, dbInfo.LogPrefixORGID, dbInfo.LogPrefixName)
				if err = tx.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Updates(map[string]interface{}{"vtap_group_lcuuid": vtapGroup.Lcuuid}).Error; err != nil {
					return err
				}
				agents = append(agents, *vtap)
			}
			if len(agents) > 0 {
				return agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, &vtapGroup, agents)
			}
			return nil
		}

		// 更新vtap_group DB
		return tx.Model(&vtapGroup).Updates(dbUpdateMap).Error
	})
	if err != nil {
		return model.VtapGroup{}, err
	}

	response, _ := a.Get(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache(userInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return response[0], nil
}

func (a *AgentGroup) Delete(lcuuid string) (resp map[string]string, err error) {
	orgID := a.resourceAccess.UserInfo.ORGID
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB

	var vtapGroup mysqlmodel.VTapGroup
	if ret := db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return map[string]string{}, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}
	if err := a.resourceAccess.CanDeleteResource(vtapGroup.TeamID, common.SET_RESOURCE_TYPE_AGENT_GROUP, vtapGroup.Lcuuid); err != nil {
		return nil, err
	}
	var agents []mysqlmodel.VTap
	if err = db.Where("vtap_group_lcuuid = ?", lcuuid).Find(&agents).Error; err != nil {
		return map[string]string{}, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}

	var defaultVtapGroup mysqlmodel.VTapGroup
	if ret := db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&defaultVtapGroup); ret.Error != nil {
		return map[string]string{}, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, "default vtap_group not found")
	}

	log.Infof("delete vtap_group (%s)", vtapGroup.Name, dbInfo.LogPrefixORGID, dbInfo.LogPrefixName)
	err = db.Transaction(func(tx *gorm.DB) error {
		if len(agents) > 0 {
			if err = agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, &defaultVtapGroup, agents); err != nil {
				return err
			}
		}
		if err = tx.Model(&mysqlmodel.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Updates(map[string]interface{}{
			"vtap_group_lcuuid": defaultVtapGroup.Lcuuid, "team_id": defaultVtapGroup.TeamID}).Error; err != nil {
			return err
		}
		if err = db.Delete(&vtapGroup).Error; err != nil {
			return err
		}
		// TODO remove after vtap_group_config is deprecated
		if err = db.Where("vtap_group_lcuuid = ?", lcuuid).Delete(&agentconf.AgentGroupConfigModel{}).Error; err != nil {
			return err
		}
		return db.Where("agent_group_lcuuid = ?", lcuuid).Delete(&agentconf.MySQLAgentGroupConfiguration{}).Error
	})
	if err != nil {
		return nil, err
	}

	refresh.RefreshCache(orgID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return map[string]string{"LCUUID": lcuuid}, nil
}
