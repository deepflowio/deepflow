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
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
	var allVTaps []metadbmodel.VTap
	var allVTapGroups []*metadbmodel.VTapGroup
	var vtapGroupLcuuids []string
	var groupToVtapLcuuids map[string][]string
	var groupToPendingVtapLcuuids map[string][]string
	var groupToDisableVtapLcuuids map[string][]string

	userInfo := a.resourceAccess.UserInfo
	dbInfo, err := metadb.GetDB(userInfo.ORGID)
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
	dbInfo, err := metadb.GetDB(userInfo.ORGID)
	if err != nil {
		return model.VtapGroup{}, err
	}
	db := dbInfo.DB

	db.Model(&metadbmodel.VTapGroup{}).Count(&vtapGroupCount)
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

	var allVTaps []metadbmodel.VTap
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

	vtapGroup := metadbmodel.VTapGroup{}
	vtapGroup.Lcuuid = lcuuid
	vtapGroup.ShortUUID = shortUUID
	vtapGroup.Name = vtapGroupCreate.Name
	vtapGroup.TeamID = vtapGroupCreate.TeamID
	vtapGroup.UserID = a.resourceAccess.UserInfo.ID
	vtapGroup.LicenseFunctions = common.AGENT_ALL_LICENSE_FUNCTIONS

	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&vtapGroup).Error; err != nil {
			return err
		}
		for _, vtap := range vtaps {
			if err := tx.Model(&metadbmodel.VTap{}).Where("id = ?", vtap.ID).Updates(map[string]interface{}{"vtap_group_lcuuid": lcuuid,
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
	db.Model(&metadbmodel.VTapGroup{}).Where("short_uuid = ?", groupID).Count(&vtapGroupCount)
	if vtapGroupCount > 0 {
		return response.ServiceError(httpcommon.RESOURCE_ALREADY_EXIST, fmt.Sprintf("id(%s) already exist", groupID))
	}
	return nil
}

func (a *AgentGroup) Update(lcuuid string, body map[string]interface{}, cfg *config.ControllerConfig) (resp model.VtapGroup, err error) {
	// 1. Prepare and validate data (outside transaction)
	toolData, err := a.prepareUpdateData(lcuuid, body, cfg)
	if err != nil {
		return model.VtapGroup{}, err
	}

	// 2. Perform permission checks (outside transaction)
	if err := a.validateUpdatePermissions(toolData); err != nil {
		return model.VtapGroup{}, err
	}

	log.Infof("update vtap_group (%s) config %v", toolData.agentGroup.Name, toolData.requestBody, toolData.db.LogPrefixORGID, toolData.db.LogPrefixName)

	// 3. Execute database operations within a transaction
	err = toolData.db.DB.Transaction(func(tx *gorm.DB) error {
		return a.executeUpdateInTransaction(tx, toolData)
	})
	if err != nil {
		return model.VtapGroup{}, err
	}

	response, _ := a.Get(map[string]interface{}{"lcuuid": lcuuid})
	refresh.RefreshCache(a.resourceAccess.UserInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return response[0], nil
}

// updateRelatedData encapsulates all data required for the update operation
type updateRelatedData struct {
	requestBody map[string]interface{}
	db          *mysql.DB

	agentGroup               *mysqlmodel.VTapGroup
	agentGroupValuesToUpdate map[string]interface{} // values to update in agent group table
	oldAgentGroupTeamID      int
	newAgentGroupTeamID      int
	agentListChanged         bool

	agentGroupConfigs     []agentconf.AgentGroupConfigModel
	userAccessedOldAgents []mysqlmodel.VTap
	userAccessedNewAgents []mysqlmodel.VTap

	agentsToRemove    []mysqlmodel.VTap
	agentsToAdd       []mysqlmodel.VTap
	defaultAgentGroup *mysqlmodel.VTapGroup
}

// prepareUpdateData prepares all data required for the update
func (a *AgentGroup) prepareUpdateData(lcuuid string, requestBody map[string]interface{}, cfg *config.ControllerConfig) (*updateRelatedData, error) {
	db, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}

	data := &updateRelatedData{
		db:                       db,
		requestBody:              requestBody,
		agentGroupValuesToUpdate: make(map[string]interface{}),
	}

	if err := db.Where("lcuuid = ?", lcuuid).First(&data.agentGroup); err.Error != nil {
		return nil, fmt.Errorf("failed to get vtap_group: %s", err.Error.Error())
	}
	data.oldAgentGroupTeamID = data.agentGroup.TeamID
	data.newAgentGroupTeamID = data.oldAgentGroupTeamID

	if err := db.Where("vtap_group_lcuuid = ?", lcuuid).Find(&data.agentGroupConfigs).Error; err != nil {
		return nil, fmt.Errorf("failed to get vtap_group configs: %s", err.Error())
	}

	if teamIDValue, ok := requestBody["TEAM_ID"]; ok {
		vtapGroupTeamIDFloat, ok := teamIDValue.(float64)
		if !ok {
			return nil, fmt.Errorf("get team id(type=%s) error", reflect.TypeOf(teamIDValue).String())
		}
		data.newAgentGroupTeamID = int(vtapGroupTeamIDFloat)
		data.agentGroupValuesToUpdate["team_id"] = teamIDValue
	}

	if nameValue, ok := requestBody["NAME"]; ok {
		data.agentGroupValuesToUpdate["name"] = nameValue
	}
	if userIDValue, ok := requestBody["USER_ID"]; ok {
		data.agentGroupValuesToUpdate["user_id"] = userIDValue
	}

	var allOldAgents []mysqlmodel.VTap
	if err := db.Where("vtap_group_lcuuid = ?", lcuuid).Find(&allOldAgents).Error; err != nil {
		return nil, fmt.Errorf("failed to get vtap_group agents: %s", err.Error())
	}
	userAccessedOldAgents, err := GetAgentByUser(a.resourceAccess.UserInfo, &a.cfg.FPermit, allOldAgents)
	if err != nil {
		return nil, err
	}
	data.userAccessedOldAgents = userAccessedOldAgents

	// Handle agent list update
	if value, ok := requestBody["VTAP_LCUUIDS"]; ok {
		data.agentListChanged = true
		agentLcuuids, ok := value.([]interface{})
		if !ok {
			return nil, fmt.Errorf("get vtap_lcuuids(type=%s) error", reflect.TypeOf(value).String())
		}

		if len(agentLcuuids) > cfg.Spec.VTapMaxPerGroup {
			return nil, response.ServiceError(
				httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED,
				fmt.Sprintf("vtap count exceeds (limit %d)", cfg.Spec.VTapMaxPerGroup),
			)
		}

		var allNewAgents []mysqlmodel.VTap
		if err := db.Where("lcuuid IN (?)", agentLcuuids).Find(&allNewAgents).Error; err != nil {
			return nil, fmt.Errorf("failed to get new vtap_group agents: %s", err.Error())
		}
		userAccessedNewAgents, err := GetAgentByUser(a.resourceAccess.UserInfo, &a.cfg.FPermit, allNewAgents)
		if err != nil {
			return nil, err
		}
		for _, agent := range userAccessedNewAgents {
			if agent.TeamID != data.newAgentGroupTeamID {
				return nil, fmt.Errorf("agent name(%s) team(%d) must equal to agent group team(%d)", agent.Name, agent.TeamID, data.newAgentGroupTeamID)
			}
		}
		data.userAccessedNewAgents = userAccessedNewAgents

		a.calculateAgentDifferences(data)

		// Agents removed from the current agent group need to be migrated to the default agent group;
		// if necessary, obtain the default agent group information
		if len(data.agentsToRemove) > 0 {
			if err := db.Where("id = ?", common.DEFAULT_VTAP_GROUP_ID).First(&data.defaultAgentGroup); err.Error != nil {
				return nil, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, "failed to get default vtap_group")
			}
		}
	}

	return data, nil
}

// calculateAgentDifferences calculates the difference between the agents to be added and removed
func (a *AgentGroup) calculateAgentDifferences(data *updateRelatedData) {
	oldAgentLcuuids := mapset.NewSet[string]()
	newAgentLcuuids := mapset.NewSet[string]()
	for _, agent := range data.userAccessedOldAgents {
		oldAgentLcuuids.Add(agent.Lcuuid)
	}
	for _, agent := range data.userAccessedNewAgents {
		newAgentLcuuids.Add(agent.Lcuuid)
	}
	agentLcuuidsToRemove := oldAgentLcuuids.Difference(newAgentLcuuids).ToSlice()
	agentLcuuidsToAdd := newAgentLcuuids.Difference(oldAgentLcuuids).ToSlice()

	for _, agent := range data.userAccessedOldAgents {
		if slices.Contains(agentLcuuidsToRemove, agent.Lcuuid) {
			data.agentsToRemove = append(data.agentsToRemove, agent)
		}
	}
	for _, agent := range data.userAccessedNewAgents {
		if slices.Contains(agentLcuuidsToAdd, agent.Lcuuid) {
			data.agentsToAdd = append(data.agentsToAdd, agent)
		}
	}
}

// validateUpdatePermissions validates the permission for the update operation
func (a *AgentGroup) validateUpdatePermissions(data *updateRelatedData) error {
	changeUserValues := make(map[string]interface{})
	teamIDValue, changeTeam := data.requestBody["TEAM_ID"]
	userIDValue, changeUser := data.requestBody["USER_ID"]

	// Following the logic before refactoring, only assign this value when the user ID changes
	if changeUser {
		changeUserValues["owner_user_id"] = userIDValue
		changeUserValues["team_id"] = teamIDValue
	}

	// Validate permission for current agent group
	if err := a.resourceAccess.CanUpdateResource(data.oldAgentGroupTeamID,
		common.SET_RESOURCE_TYPE_AGENT_GROUP, data.agentGroup.Lcuuid, changeUserValues); err != nil {
		return err
	}

	// Validate permission for agent group config
	if changeTeam && changeUser {
		for _, config := range data.agentGroupConfigs {
			if err := a.resourceAccess.CanUpdateResource(data.oldAgentGroupTeamID,
				common.SET_RESOURCE_TYPE_AGENT_GROUP_CONFIG, *config.Lcuuid, changeUserValues); err != nil {
				return err
			}
		}
	}

	// Validate permission for agents in agent group
	if _, ok := data.requestBody["ENABLE"]; ok {
		for _, agent := range data.userAccessedOldAgents {
			if err := a.resourceAccess.CanUpdateResource(agent.TeamID,
				common.SET_RESOURCE_TYPE_AGENT, agent.Lcuuid, nil); err != nil {
				return fmt.Errorf("%w no permission to update agent(%s)", err, agent.Name)
			}
		}
	}

	return nil
}

// executeUpdateInTransaction performs the database operations within a transaction
func (a *AgentGroup) executeUpdateInTransaction(tx *gorm.DB, data *updateRelatedData) error {
	// Handle state update
	if stateValue, ok := data.requestBody["STATE"]; ok {
		if err := tx.Model(&mysqlmodel.VTap{}).Where("vtap_group_lcuuid = ?", data.agentGroup.Lcuuid).Update("state", stateValue).Error; err != nil {
			return err
		}
	}

	// Handle enable state update
	if enableValue, ok := data.requestBody["ENABLE"]; ok {
		if err := tx.Model(&mysqlmodel.VTap{}).Where("vtap_group_lcuuid = ?", data.agentGroup.Lcuuid).Update("enable", enableValue).Error; err != nil {
			return err
		}
	}

	// Handle agent list update
	if data.agentListChanged {
		if err := a.updateAgentAssignments(tx, data); err != nil {
			return err
		}
	}

	// Handle agent group self update
	if len(data.agentGroupValuesToUpdate) > 0 {
		if err := tx.Model(data.agentGroup).Updates(data.agentGroupValuesToUpdate).Error; err != nil {
			return err
		}
	}

	return nil
}

// updateAgentAssignments handle the agent list update
func (a *AgentGroup) updateAgentAssignments(tx *gorm.DB, data *updateRelatedData) error {
	// Handle agents removed from the current agent group
	if len(data.agentsToRemove) > 0 {
		valuesToUpdate := map[string]interface{}{"vtap_group_lcuuid": data.defaultAgentGroup.Lcuuid}
		for _, agent := range data.agentsToRemove {
			log.Infof("update agent name(%s), detail: vtap_group_lcuuid(%s -> %s)",
				agent.Name, agent.VtapGroupLcuuid, data.defaultAgentGroup.Lcuuid, data.db.LogPrefixORGID, data.db.LogPrefixName)

			if err := tx.Model(&mysqlmodel.VTap{}).Where("id = ?", agent.ID).Updates(valuesToUpdate).Error; err != nil {
				return err
			}
		}
		if err := agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, data.defaultAgentGroup, data.agentsToRemove); err != nil {
			return err
		}
	}

	// Handle agents added to the current agent group
	if len(data.agentsToAdd) > 0 {
		valuesToUpdate := map[string]interface{}{"vtap_group_lcuuid": data.agentGroup.Lcuuid}
		for _, agent := range data.agentsToAdd {
			log.Infof("update agent name(%s), detail: vtap_group_lcuuid(%s -> %s)",
				agent.Name, agent.VtapGroupLcuuid, data.agentGroup.Lcuuid, data.db.LogPrefixORGID, data.db.LogPrefixName)

			if err := tx.Model(&mysqlmodel.VTap{}).Where("id = ?", agent.ID).Updates(valuesToUpdate).Error; err != nil {
				return err
			}
		}
		if err := agentlicense.UpdateAgentLicenseFunction(tx, a.resourceAccess.UserInfo.ID, data.agentGroup, data.agentsToAdd); err != nil {
			return err
		}
	}

	return nil
}

func (a *AgentGroup) Delete(lcuuid string) (resp map[string]string, err error) {
	orgID := a.resourceAccess.UserInfo.ORGID
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB

	var vtapGroup metadbmodel.VTapGroup
	if ret := db.Where("lcuuid = ?", lcuuid).First(&vtapGroup); ret.Error != nil {
		return map[string]string{}, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}
	if err := a.resourceAccess.CanDeleteResource(vtapGroup.TeamID, common.SET_RESOURCE_TYPE_AGENT_GROUP, vtapGroup.Lcuuid); err != nil {
		return nil, err
	}
	var agents []metadbmodel.VTap
	if err = db.Where("vtap_group_lcuuid = ?", lcuuid).Find(&agents).Error; err != nil {
		return map[string]string{}, response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_group (%s) not found", lcuuid))
	}

	var defaultVtapGroup metadbmodel.VTapGroup
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
		if err = tx.Model(&metadbmodel.VTap{}).Where("vtap_group_lcuuid = ?", lcuuid).Updates(map[string]interface{}{
			"vtap_group_lcuuid": defaultVtapGroup.Lcuuid, "team_id": defaultVtapGroup.TeamID}).Error; err != nil {
			return err
		}
		if err = tx.Delete(&vtapGroup).Error; err != nil {
			return err
		}
		// TODO remove after vtap_group_config is deprecated
		if err = tx.Where("vtap_group_lcuuid = ?", lcuuid).Delete(&agentconf.AgentGroupConfigModel{}).Error; err != nil {
			return err
		}
		return tx.Where("agent_group_lcuuid = ?", lcuuid).Delete(&agentconf.MySQLAgentGroupConfiguration{}).Error
	})
	if err != nil {
		return nil, err
	}

	refresh.RefreshCache(orgID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	return map[string]string{"LCUUID": lcuuid}, nil
}
