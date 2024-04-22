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
	"fmt"
	"reflect"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const ORG_TABLE = "org"

func GetORGIDs() ([]int, error) {
	ids := []int{common.DEFAULT_ORG_ID}
	if oids, err := GetNonDefaultORGIDs(); err != nil {
		return ids, err
	} else {
		ids = append(ids, oids...)
	}
	return ids, nil
}

func GetNonDefaultORGIDs() ([]int, error) {
	ids := make([]int, 0)
	var orgTable string
	err := DefaultDB.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", GetConfig().Database, ORG_TABLE)).Scan(&orgTable).Error
	if err != nil {
		log.Errorf("failed to check org table: %v", err.Error())
		return ids, err
	}
	if orgTable == "" {
		return ids, nil
	}

	var orgs []*Org
	if err := DefaultDB.Where("loop_id != ?", common.DEFAULT_ORG_ID).Find(&orgs).Error; err != nil {
		log.Errorf("failed to get org ids: %v", err.Error())
		return ids, err
	}
	for _, org := range orgs {
		ids = append(ids, org.ORGID)
	}
	return ids, nil
}

// SyncDefaultOrgData synchronizes a slice of data items of any type T to all organization databases except the default one.
// It assumes each data item has an "ID" field (with a json tag "ID") serving as the primary key. During upsertion,
// fields are updated based on their "gorm" tags, and empty string values are converted to null in the database.
//
// Parameters:
// - data: A slice of data items of any type T to be synchronized. The type T must have an "ID" field tagged as the primary key.
func SyncDefaultOrgData[T any](data []T) error {
	if len(data) == 0 {
		return nil
	}

	// get fields to update
	dataType := reflect.TypeOf(data[0])
	var fields []string
	for i := 0; i < dataType.NumField(); i++ {
		field := dataType.Field(i)
		dbTag := field.Tag.Get("gorm")
		if dbTag != "" {
			columnName := GetColumnNameFromTag(dbTag)
			if columnName != "" {
				fields = append(fields, columnName)
			}
		}
	}

	for orgID, db := range dbs.orgIDToDB {
		if orgID == DefaultDB.ORGID {
			continue
		}

		err := db.Transaction(func(tx *gorm.DB) error {
			// delete
			var existingIDs []int
			var t T
			if err := db.Model(&t).Pluck("id", &existingIDs).Error; err != nil {
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
					if err := db.Where("id = ?", id).Delete(&t).Error; err != nil {
						return err
					}
				}
			}

			// add or update
			if err := db.Clauses(clause.OnConflict{
				DoUpdates: clause.AssignmentColumns(fields), // `UpdateAll: true,` can not update time
			}).Save(&data).Error; err != nil {
				return fmt.Errorf("failed to sync data: %v", err)
			}
			return nil
		})
		if err != nil {
			log.Errorf("org(id:%d, name:%s) error: %s", db.ORGID, db.Name, err.Error())
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
