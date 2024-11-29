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
	"sort"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/model"
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
	err := DefaultDB.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", GetConfig().Database, ORG_TABLE)).Scan(&orgTable).Error
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

type SyncORGConfig struct {
	HardDelete     bool
	WhereCondition []interface{}
	ExcludeFields  []string
}

type SyncORGConfigOption func(opts *SyncORGConfig)

func WithHardDelete() SyncORGConfigOption {
	return func(opts *SyncORGConfig) {
		opts.HardDelete = true
	}
}

func WithWhereCondition(condition ...interface{}) SyncORGConfigOption {
	return func(opts *SyncORGConfig) {
		opts.WhereCondition = condition
	}
}

func WithExcludeFields(fields []string) SyncORGConfigOption {
	return func(opts *SyncORGConfig) {
		opts.ExcludeFields = fields
	}
}

// SyncDefaultOrgData synchronizes a slice of data items of any type T to all organization databases except the default one.
// It assumes each data item has an "ID" field (with a json tag "ID") serving as the primary key. During upsertion,
// fields are updated based on their "gorm" tags, and empty string values are converted to null in the database.
//
// Parameters:
// - uniqueKey: A unique identifier for the data items.
// - data: A slice of data items of any type T to be synchronized. The type T must have an "ID" field tagged as the primary key.
func SyncDefaultORGData[T any](uniqueKey string, data []T, options ...SyncORGConfigOption) error {
	if len(data) == 0 {
		return nil
	}

	cfg := &SyncORGConfig{}
	for _, option := range options {
		option(cfg)
	}

	excludeFieldsMap := make(map[string]bool)
	for _, field := range cfg.ExcludeFields {
		excludeFieldsMap[field] = true
	}

	// get fields to update
	dataType := reflect.TypeOf(data[0])
	var fields []string
	var structFieldName string
	for i := 0; i < dataType.NumField(); i++ {
		field := dataType.Field(i)
		dbTag := field.Tag.Get("gorm")
		if dbTag != "" {
			columnName := GetColumnNameFromTag(dbTag)
			if columnName == uniqueKey {
				structFieldName = field.Name
			}
			if columnName != "" && !excludeFieldsMap[columnName] {
				fields = append(fields, columnName)
			}
		}
	}
	if structFieldName == "" {
		return fmt.Errorf("no struct field found for unique key: %s", uniqueKey)
	}
	log.Infof("weiqiang fields to update: %v", fields)

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
			log.Errorf("get org id (%d) mysql session failed", orgID)
			continue
		}

		db := dbInfo.DB
		err = db.Transaction(func(tx *gorm.DB) error {
			// delete
			var existingKeys []interface{}
			var t T
			query := tx.Model(&t)
			if len(cfg.WhereCondition) == 1 {
				query = query.Where(cfg.WhereCondition[0])
			} else if len(cfg.WhereCondition) > 1 {
				query = query.Where(cfg.WhereCondition[0], cfg.WhereCondition[1:]...)
			}
			if err := query.Model(&t).Pluck(uniqueKey, &existingKeys).Error; err != nil {
				return err
			}
			existingKeyMap := make(map[interface{}]bool)
			for _, key := range existingKeys {
				switch v := key.(type) {
				case []byte:
					existingKeyMap[string(v)] = true
				default:
					existingKeyMap[v] = true
				}
			}
			log.Infof("weiqiang org(%v) existingKeyMap: %v", orgID, existingKeyMap)
			for _, item := range data {
				val := reflect.ValueOf(item)
				field := val.FieldByName(structFieldName)
				if !field.IsValid() {
					return fmt.Errorf("field %s not found in the struct", structFieldName)
				}
				key := field.Interface()
				switch v := key.(type) {
				case []byte:
					existingKeyMap[string(v)] = false
				default:
					existingKeyMap[v] = false
				}
			}
			log.Infof("weiqiang org(%v) existingKeyMap: %v", orgID, existingKeyMap)
			for key, exists := range existingKeyMap {
				if exists {
					if cfg.HardDelete {
						err = tx.Unscoped().Where(fmt.Sprintf("%s = ?", uniqueKey), key).Delete(&t).Error
					} else {
						err = tx.Where(fmt.Sprintf("%s = ?", uniqueKey), key).Delete(&t).Error
					}
					if err != nil {
						return err
					}
				}
			}

			log.Infof("weiqiang org(%v) save data: %v", orgID, data)

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
