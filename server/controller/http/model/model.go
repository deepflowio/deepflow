/**
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

package model

import (
	agentconf "github.com/deepflowio/deepflow/server/agent_config"
)

type ORGDataCreate struct {
	ORGID int `json:"ORGANIZATION_ID" binding:"required"`
}

type PageParams struct {
	PageIndex int `schema:"page_index,omitempty"`
	PageSize  int `schema:"page_size,omitempty"`
}

type VTapInterfaceQuery struct {
	PageParams

	TeamID     int `schema:"team_id,omitempty"`
	UserID     int `schema:"user_id,omitempty"`
	DeviceType int `schema:"device_type,omitempty"`
	VTapType   int `schema:"vtap_type,omitempty"`

	FuzzyName       string `schema:"fuzzy_name,omitempty"`
	FuzzyMAC        string `schema:"fuzzy_mac,omitempty"`
	FuzzyDeviceName string `schema:"fuzzy_device_name,omitempty"`
	FuzzyVTapName   string `schema:"fuzzy_vtap_name,omitempty"`
	FuzzyTapName    string `schema:"fuzzy_tap_name,omitempty"`
	FuzzyTapMAC     string `schema:"fuzzy_tap_mac,omitempty"`
}

// AgentGroupConfigChangelogQuery 定义了查询采集器配置变更记录的请求参数
type AgentGroupConfigChangelogQuery struct {
	TimeStart int    `schema:"time_start" json:"time_start" binding:"required"` // 查询时间范围开始
	TimeEnd   int    `schema:"time_end" json:"time_end" binding:"required"`     // 查询时间范围结束
	Interval  string `schema:"interval" json:"interval" binding:"required"`     // 查询时间粒度
}

// AgentGroupConfigChangelogCreate 定义了创建采集器配置变更记录的请求参数
type AgentGroupConfigChangelogCreate struct {
	UserID   int    `json:"USER_ID" binding:"required"`   // 变更人（用户ID）
	Remarks  string `json:"REMARKS" binding:"required"`   // 变更备注
	YamlDiff string `json:"YAML_DIFF" binding:"required"` // 变更 Diff
}

// AgentGroupConfigChangelogUpdate 定义了更新采集器配置变更记录的请求参数
type AgentGroupConfigChangelogUpdate struct {
	Remarks string `json:"REMARKS" binding:"required"` // 变更备注
}

// AgentGroupConfigChangelogTrendResponse 定义了采集器配置变更记录的响应参数
type AgentGroupConfigChangelogTrendResponse struct {
	TimeSlot   string                              `json:"TIME_SLOT"` // 时间槽，用于获取趋势时的聚合展示，仅在获取趋势时返回
	Count      int                                 `json:"COUNT"`     // 该时间槽内的记录数，用于获取趋势时的聚合展示，仅在获取趋势时返回
	ChangeLogs []AgentGroupConfigChangelogResponse `json:"CHANGELOGS,omitempty"`
}

// AgentGroupConfigChangelogResponse 定义了采集器配置变更记录的响应参数
type AgentGroupConfigChangelogResponse struct {
	agentconf.MetadbAgentGroupConfigurationChangelog
}

// AgentGroupConfigQuery 定义了查询采集器配置的请求参数
type AgentGroupConfigQuery struct {
	AgentGroupLcuuid string `schema:"agent_group_lcuuid,omitempty" json:"agent_group_lcuuid,omitempty"` // 采集器组 LCUUID
}

// AgentGroupConfigResponse 定义了采集器配置的响应参数
type AgentGroupConfigResponse struct {
	agentconf.MySQLAgentGroupConfiguration
}
