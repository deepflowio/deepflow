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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChPolicy struct {
	UpdaterComponent[metadbmodel.ChPolicy, PolicyKey]
}

func NewChPolicy() *ChPolicy {
	updater := &ChPolicy{
		newUpdaterComponent[metadbmodel.ChPolicy, PolicyKey](
			RESOURCE_TYPE_CH_POLICY,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChPolicy) generateNewData(db *metadb.DB) (map[PolicyKey]metadbmodel.ChPolicy, bool) {
	var (
		pcapPolicys []metadbmodel.PcapPolicy
		npbPolicys  []metadbmodel.NpbPolicy
	)
	err := db.Unscoped().Select("id", "name", "policy_acl_group_id", "team_id").Find(&pcapPolicys).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	err = db.Unscoped().Select("id", "name", "policy_acl_group_id", "npb_tunnel_id", "team_id").Find(&npbPolicys).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[PolicyKey]metadbmodel.ChPolicy)
	for _, pcapPolicy := range pcapPolicys {
		keyToItem[PolicyKey{ACLGID: pcapPolicy.PolicyACLGroupID, TunnelType: 0}] = metadbmodel.ChPolicy{
			ACLGID:     pcapPolicy.PolicyACLGroupID,
			TunnelType: 0, // Pcap
			ID:         pcapPolicy.ID,
			Name:       pcapPolicy.Name,
			TeamID:     pcapPolicy.TeamID,
		}
	}
	for _, npbPolicy := range npbPolicys {
		keyToItem[PolicyKey{ACLGID: npbPolicy.PolicyACLGroupID, TunnelType: 1}] = metadbmodel.ChPolicy{
			ACLGID:     npbPolicy.PolicyACLGroupID,
			TunnelType: 1, // Npb
			ID:         npbPolicy.ID,
			Name:       npbPolicy.Name,
			TeamID:     npbPolicy.TeamID,
		}
	}
	return keyToItem, true
}

func (p *ChPolicy) generateKey(dbItem metadbmodel.ChPolicy) PolicyKey {
	return PolicyKey{ACLGID: dbItem.ACLGID, TunnelType: dbItem.TunnelType}
}

func (p *ChPolicy) generateUpdateInfo(oldItem, newItem metadbmodel.ChPolicy) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.ID != newItem.ID {
		updateInfo["id"] = newItem.ID
	}
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
