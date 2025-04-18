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
