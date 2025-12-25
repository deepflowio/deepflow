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

package agent

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

func NewAgentGroupConfigChangelogService(userInfo *model.UserInfo, fpermitCfg ctrlcommon.FPermit) *ConfigChangelog {
	return &ConfigChangelog{
		ResourceAccess: service.NewResourceAccess(fpermitCfg, common.NewUserInfo(userInfo.Type, userInfo.ID, userInfo.ORGID)),
	}
}

type ConfigChangelog struct {
	*service.ResourceAccess
}

// Get retrieves agent group configuration changelog records within the specified time range
// It returns a list of changelog records grouped by the specified interval (1h or 1d)
func (c *ConfigChangelog) Get(configLcuuid string, query *model.AgentGroupConfigChangelogQuery) ([]*model.AgentGroupConfigChangelogTrendResponse, error) {
	dbInfo, err := metadb.GetDB(c.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}

	var config agentconf.MySQLAgentGroupConfiguration
	err = dbInfo.DB.Where("lcuuid = ?", configLcuuid).First(&config).Error
	if err != nil {
		return nil, err
	}

	// Parse time range from Unix timestamp
	timeStart := time.Unix(int64(query.TimeStart), 0)
	timeEnd := time.Unix(int64(query.TimeEnd), 0)

	// Validate time range
	if timeStart.After(timeEnd) {
		return nil, fmt.Errorf("time_start must be before time_end")
	}

	// Determine interval based on time range if not explicitly provided
	interval := query.Interval
	if interval == "" {
		interval = c.determineInterval(timeStart, timeEnd)
	}

	// Validate interval
	if interval != "1h" && interval != "1d" {
		return nil, fmt.Errorf("interval must be either '1h' or '1d'")
	}

	// Query all changelog records within time range
	var changelogs []agentconf.MetadbAgentGroupConfigurationChangelog
	err = dbInfo.DB.Where("agent_group_configuration_id = ? AND created_at >= ? AND created_at <= ?", config.ID, timeStart, timeEnd).
		Order("created_at DESC").
		Find(&changelogs).Error
	if err != nil {
		return nil, err
	}

	// Aggregate changelog records by time interval (including zero-count slots)
	responses := c.getAggregatedChangelogs(changelogs, interval, timeStart, timeEnd)

	return responses, nil
}

// determineInterval determines the appropriate time interval based on the time range
// Returns "1h" if time range <= 3 days, otherwise returns "1d"
func (c *ConfigChangelog) determineInterval(timeStart, timeEnd time.Time) string {
	duration := timeEnd.Sub(timeStart)
	threeDays := 3 * 24 * time.Hour

	if duration <= threeDays {
		return "1h"
	}
	return "1d"
}

// getAggregatedChangelogs aggregates changelog records by time interval
// It groups records by time slot (1h or 1d) and attaches aggregation metadata
// It also fills in zero-count time slots to ensure continuous time series
func (c *ConfigChangelog) getAggregatedChangelogs(changelogs []agentconf.MetadbAgentGroupConfigurationChangelog, interval string, timeStart, timeEnd time.Time) []*model.AgentGroupConfigChangelogTrendResponse {
	// Group changelogs by time slot
	timeSlotMap := make(map[string][]model.AgentGroupConfigChangelogResponse)
	for i := range changelogs {
		var timeSlot string
		if interval == "1h" {
			// Truncate to hour
			timeSlot = changelogs[i].CreatedAt.Truncate(time.Hour).Format("2006-01-02 15:00:00")
		} else {
			// Truncate to day
			timeSlot = changelogs[i].CreatedAt.Truncate(24 * time.Hour).Format("2006-01-02 00:00:00")
		}
		timeSlotMap[timeSlot] = append(
			timeSlotMap[timeSlot], model.AgentGroupConfigChangelogResponse{
				MetadbAgentGroupConfigurationChangelog: changelogs[i],
			})
	}

	// Generate all time slots in the range (including zero-count slots)
	var duration time.Duration
	if interval == "1h" {
		duration = time.Hour
	} else {
		duration = 24 * time.Hour
	}

	// Truncate start and end times to the interval boundary
	start := timeStart.Truncate(duration)
	end := timeEnd.Truncate(duration)
	if end.Before(timeEnd) {
		end = end.Add(duration)
	}

	// Build response with all time slots
	var responses []*model.AgentGroupConfigChangelogTrendResponse
	for current := start; !current.After(end); current = current.Add(duration) {
		timeSlot := current.Format("2006-01-02 15:00:00")
		if interval == "1d" {
			timeSlot = current.Format("2006-01-02 00:00:00")
		}

		logs, exists := timeSlotMap[timeSlot]
		if !exists {
			logs = []model.AgentGroupConfigChangelogResponse{}
		}

		response := &model.AgentGroupConfigChangelogTrendResponse{
			TimeSlot:   timeSlot,
			Count:      len(logs),
			ChangeLogs: logs,
		}
		responses = append(responses, response)
	}

	return responses
}

// Create creates a new agent group configuration changelog record
func (c *ConfigChangelog) Create(configLcuuid string, create *model.AgentGroupConfigChangelogCreate) (*model.AgentGroupConfigChangelogResponse, error) {
	log.Infof("create agent group config changelog: %v, user info: %v", create, c.UserInfo)

	dbInfo, err := metadb.GetDB(c.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}

	var config agentconf.MySQLAgentGroupConfiguration
	err = dbInfo.DB.Where("lcuuid = ?", configLcuuid).First(&config).Error
	if err != nil {
		return nil, err
	}

	// Create changelog record
	changelog := agentconf.MetadbAgentGroupConfigurationChangelog{
		Lcuuid:             ctrlcommon.GenerateUUID(time.Now().GoString()),
		AgentGroupConfigID: config.ID,
		YamlDiff:           create.YamlDiff,
		UserID:             create.UserID,
		Remarks:            create.Remarks,
	}

	err = dbInfo.DB.Create(&changelog).Error
	if err != nil {
		return nil, err
	}

	return &model.AgentGroupConfigChangelogResponse{
		MetadbAgentGroupConfigurationChangelog: changelog,
	}, nil
}

// Update updates the remarks field of an existing agent group configuration changelog record
func (c *ConfigChangelog) Update(lcuuid string, update *model.AgentGroupConfigChangelogUpdate) (*model.AgentGroupConfigChangelogResponse, error) {
	dbInfo, err := metadb.GetDB(c.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}

	// Find the changelog record
	var changelog agentconf.MetadbAgentGroupConfigurationChangelog
	err = dbInfo.DB.Where("lcuuid = ?", lcuuid).First(&changelog).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("changelog record with lcuuid %s not found", lcuuid)
		}
		return nil, err
	}

	// Update remarks
	err = dbInfo.DB.Model(&changelog).Update("remarks", update.Remarks).Error
	if err != nil {
		return nil, err
	}

	// Reload the updated record to get the new updated_at
	err = dbInfo.DB.Where("lcuuid = ?", lcuuid).First(&changelog).Error
	if err != nil {
		return nil, err
	}

	return &model.AgentGroupConfigChangelogResponse{
		MetadbAgentGroupConfigurationChangelog: changelog,
	}, nil
}
