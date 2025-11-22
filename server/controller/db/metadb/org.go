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

package metadb

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

const ORG_TABLE = "org"

// GetORGIDs returns a slice of organization IDs, including the default organization ID, but not including the soft deleted organization IDs.
func GetORGIDs() ([]int, error) {
	ids := []int{common.DEFAULT_ORG_ID}
	if oids, err := GetNonDefaultORGIDs(); err != nil {
		return ids, err
	} else {
		ids = append(ids, oids...)
	}
	return ids, nil
}

// GetNonDefaultORGIDs returns a slice of organization IDs, not including the default organization ID and the soft deleted organization IDs.
func GetNonDefaultORGIDs() ([]int, error) {
	ids := make([]int, 0)
	exists, err := CheckIfORGTableExists()
	if err != nil || !exists {
		return ids, err
	}

	var orgs []*model.ORG
	if err := DefaultDB.Where("org_id != ?", common.DEFAULT_ORG_ID).Find(&orgs).Error; err != nil {
		log.Errorf("failed to get org ids: %v", err.Error())
		return ids, err
	}
	for _, org := range orgs {
		ids = append(ids, org.ORGID)
	}
	sort.Ints(ids)
	return ids, nil
}

func GetDeletedORGIDs() ([]int, error) {
	ids := make([]int, 0)
	var orgs []*model.ORG
	if err := DefaultDB.Unscoped().Find(&orgs).Error; err != nil {
		log.Errorf("failed to get orgs: %s", err.Error())
		return ids, err
	}
	for _, org := range orgs {
		if org.DeletedAt.Valid {
			ids = append(ids, org.ORGID)
		}
	}
	return ids, nil
}

func CheckIfORGTableExists() (bool, error) {
	var orgTable string
	err := DefaultDB.Raw(DefaultDB.SqlFmt.SelectTable(ORG_TABLE)).Scan(&orgTable).Error
	if err != nil {
		log.Errorf("failed to check org table: %v", err.Error())
		return false, err
	}
	if orgTable == "" {
		return false, nil
	}
	return true, nil
}

func CheckORGNumberAndLog() ([]int, error) {
	orgIDs, err := GetORGIDs()
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("the number of organizations is %d. If you see a `Too many connections` error in the logs, please increase the `max_connections` setting in MySQL.", len(orgIDs))
	if len(orgIDs) > 20 {
		log.Warning(msg)
	} else if len(orgIDs) > 10 {
		log.Info(msg)
	}
	return orgIDs, nil
}

// SyncDefaultOrgData synchronizes a slice of data items of any type T to all organization databases except the default one.
// It assumes each data item has an "ID" field (with a json tag "ID") serving as the primary key. During upsertion,
// fields are updated based on their "gorm" tags, and empty string values are converted to null in the database.
//
// Parameters:
// - data: A slice of data items of any type T to be synchronized. The type T must have an "ID" field tagged as the primary key.
func SyncDefaultOrgData[T any](data []T, excludeFields []string) error {
	if len(data) == 0 {
		return nil
	}

	excludeFieldsMap := make(map[string]bool)
	for _, field := range excludeFields {
		excludeFieldsMap[field] = true
	}

	// get fields to update
	dataType := reflect.TypeOf(data[0])
	var fields []string
	for i := 0; i < dataType.NumField(); i++ {
		field := dataType.Field(i)
		dbTag := field.Tag.Get("gorm")
		if dbTag != "" {
			columnName := GetColumnNameFromTag(dbTag)
			if columnName != "" && !excludeFieldsMap[columnName] {
				fields = append(fields, columnName)
			}
		}
	}

	orgIDs, err := GetORGIDs()
	if err != nil {
		return err
	}

	for _, orgID := range orgIDs {
		if orgID == DefaultDB.ORGID {
			continue
		}
		dbInfo, err := GetDB(orgID)
		if err != nil {
			log.Errorf("get org id (%d) metadb session failed", orgID)
			continue
		}

		db := dbInfo.DB
		err = db.Transaction(func(tx *gorm.DB) error {
			// delete
			var existingIDs []int
			var t T
			if err := tx.Model(&t).Pluck("id", &existingIDs).Error; err != nil {
				return err
			}
			existingIDMap := make(map[int]bool)
			for _, id := range existingIDs {
				existingIDMap[id] = true
			}
			for _, item := range data {
				id := reflect.ValueOf(item).FieldByName("ID").Int()
				existingIDMap[int(id)] = false
			}
			for id, exists := range existingIDMap {
				if exists {
					if err := tx.Where("id = ?", id).Delete(&t).Error; err != nil {
						return err
					}
				}
			}

			// add or update
			if err := tx.Clauses(clause.OnConflict{
				DoUpdates: clause.AssignmentColumns(fields), // `UpdateAll: true,` can not update time
			}).Save(&data).Error; err != nil {
				return fmt.Errorf("failed to sync data: %v", err)
			}
			return nil
		})
		if err != nil {
			log.Errorf("%s", err.Error(), dbInfo.LogPrefixORGID)
		}
	}
	return nil
}

// getTagNameFromTag extracts the tag value for a given prefix from a struct field's tag string.
func getTagNameFromTag(tag, prefix string) string {
	start := strings.Index(tag, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)
	rest := tag[start:]

	end := strings.Index(rest, ";")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// GetColumnNameFromTag extracts the column name from a struct field's "gorm" tag.
// Parameters:
// - tag: The "gorm" tag string from a struct field.
// Returns:
//   - The extracted column name if the "column" prefix is present in the tag. If the "column"
//     prefix is not found, or if there's no value for the "column" prefix, an empty string is returned.
//
// Example:
// If the tag is `gorm:"column:ip;unique"`, the function returns "ip".
func GetColumnNameFromTag(tag string) string {
	return getTagNameFromTag(tag, "column:")
}

func DoOnAllDBs(execFunc func(*DB) error) error {
	orgIDs, err := GetORGIDs()
	if err != nil {
		return err
	}
	for _, orgID := range orgIDs {
		db, err := GetDB(orgID)
		if err != nil {
			log.Errorf("failed to get db info: %v", err, db.LogPrefixORGID, db.LogPrefixName)
			continue
		}
		if err := execFunc(db); err != nil {
			log.Errorf("failed to execute function: %v", err, db.LogPrefixORGID, db.LogPrefixName)
			return err
		}
	}
	return nil
}
