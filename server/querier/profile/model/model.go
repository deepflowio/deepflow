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

package model

type ProfileTracing struct {
	AppService          string `json:"app_service" binding:"required"`
	ProfileEventType    string `json:"profile_event_type" binding:"required"`
	ProfileLanguageType string `json:"profile_language_type" binding:"required"`
	TagFilter           string `json:"tag_filter"`
	GroupBy             string `json:"group_by"`
	TimeStart           int    `json:"time_start" binding:"required"`
	TimeEnd             int    `json:"time_end" binding:"required"`
	Debug               bool   `json:"debug"`
}

type ProfileTreeNode struct {
	ProfileLocationStr   string   `json:"profile_location_str"`
	NodeID               string   `json:"node_id"`
	ProfileNodeIDS       []int    `json:"profile_node_ids"`
	ParentNodeIDS        []string `json:"parent_node_ids"`
	ProfileParentNodeIDS []int    `json:"profile_parent_node_ids"`
	SelfValue            int      `json:"self_value"`
	TotalValue           int      `json:"total_value"`
}
