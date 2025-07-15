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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

var DomainToTeamID map[string]int
var SubDomainToTeamID map[string]int
var DomainToDomainID map[string]int
var SubDomainToSubDomainID map[string]int
var VTapIDToTeamID map[int]int

func GetTeamInfo(db *mysql.DB) {
	var domains []mysqlmodel.Domain
	var subDomains []mysqlmodel.SubDomain
	var vTaps []mysqlmodel.VTap
	err := db.Unscoped().Find(&domains).Error
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return
	}
	err = db.Unscoped().Find(&subDomains).Error
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return
	}
	err = db.Unscoped().Select("id", "team_id").Find(&vTaps).Error
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return
	}
	domainToTeamID := map[string]int{}
	subDomainToTeamID := map[string]int{}
	domainToDomainID := map[string]int{}
	subDomainToSubDomainID := map[string]int{}
	vTapIDToTeamID := map[int]int{}
	// domain
	for _, domain := range domains {
		domainToTeamID[domain.Lcuuid] = domain.TeamID
		domainToDomainID[domain.Lcuuid] = domain.ID
	}
	// sub_domain
	for _, subDomain := range subDomains {
		subDomainToTeamID[subDomain.Lcuuid] = subDomain.TeamID
		subDomainToSubDomainID[subDomain.Lcuuid] = subDomain.ID
	}
	// vtap
	for _, vTap := range vTaps {
		vTapIDToTeamID[vTap.ID] = vTap.TeamID
	}
	DomainToTeamID = domainToTeamID
	SubDomainToTeamID = subDomainToTeamID
	DomainToDomainID = domainToDomainID
	SubDomainToSubDomainID = subDomainToSubDomainID
	VTapIDToTeamID = vTapIDToTeamID
}

func GetTeamID(domainUUID, subDomainUUID string) (int, error) {
	if v, ok := SubDomainToTeamID[subDomainUUID]; ok {
		return v, nil
	}
	if v, ok := DomainToTeamID[domainUUID]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("can not get team id domain(%s) subdomain(%s)", domainUUID, subDomainUUID)
}
