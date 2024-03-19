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

package mysql

import (
	"errors"
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
)

const ORG_TABLE = "org"

func GetOrgIDs() ([]int, error) {
	ids := []int{common.DEFAULT_ORG_ID}
	var orgTable string
	err := DefaultDB.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", GetConfig().Database, ORG_TABLE)).Scan(&orgTable).Error
	if err != nil {
		err = errors.New(fmt.Sprintf("check org table failed: %v", err))
		log.Error(err.Error())
		return ids, err
	}
	if orgTable == "" {
		return ids, nil
	}

	var orgs []*Org
	if err := DefaultDB.Find(&orgs); err != nil {
		return ids, errors.New(fmt.Sprintf("failed to get org ids: %v", err))
	}
	for _, org := range orgs {
		if slices.Contains(ids, org.ID) {
			continue
		}
		ids = append(ids, org.ID)
	}
	return ids, nil
}
