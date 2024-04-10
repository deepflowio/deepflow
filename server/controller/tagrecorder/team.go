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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var DomainToTeamID map[string]int
var DomainToDomainID map[string]int
var VTapIDToTeamID map[int]int

func GetTeamInfo(db *mysql.DB) {
	var domains []mysql.Domain
	var vTaps []mysql.VTap
	err := db.Unscoped().Find(&domains).Error
	if err != nil {
		log.Error(err)
		return
	}
	err = db.Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Error(err)
		return
	}
	domainToTeamID := map[string]int{}
	domainToDomainID := map[string]int{}
	vTapIDToTeamID := map[int]int{}
	// domain
	for _, domain := range domains {
		domainToTeamID[domain.Lcuuid] = domain.TeamID
		domainToDomainID[domain.Lcuuid] = domain.ID
	}
	// vtap
	for _, vTap := range vTaps {
		vTapIDToTeamID[vTap.ID] = vTap.TeamID
	}
	DomainToTeamID = domainToTeamID
	DomainToDomainID = domainToDomainID
	VTapIDToTeamID = vTapIDToTeamID
}
