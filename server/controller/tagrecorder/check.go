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

package tagrecorder

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	msgconstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
)

func check[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel,
	CT MySQLChModel, KT ChModelKey](component *SubscriberComponent[MUPT, MUT, MT, CT, KT]) error {

	var resources []MT
	if err := mysql.Db.Unscoped().Find(&resources).Error; err != nil {
		err := errors.New(dbQueryResourceFailed(component.resourceTypeName, err))
		log.Error(err)
		return err
	}
	var newItems []CT
	for _, resource := range resources {
		_, targets := component.subscriberDG.sourceToTarget(&resource)
		newItems = append(newItems, targets...)
	}

	var oldItems []CT
	var err error
	if component.resourceTypeName == RESOURCE_TYPE_CH_GPROCESS {
		oldItems, err = query.FindInBatchesObj[CT](mysql.Db.Unscoped())
	} else {
		err = mysql.Db.Unscoped().Find(&oldItems).Error
	}
	if err != nil {
		err := errors.New(dbQueryResourceFailed(component.resourceTypeName, err))
		log.Error(err)
		return err
	}

	return compareAndCheck(oldItems, newItems)
}

func compareAndCheck[CT MySQLChModel](oldItems, newItems []CT) error {
	if len(newItems) == 0 && len(oldItems) == 0 {
		return nil
	}

	newStr := make([]string, len(newItems))
	oldStr := make([]string, len(oldItems))
	newStrByte, err := json.Marshal(newStr)
	if err != nil {
		return fmt.Errorf("marshal new ch data failed, %v", err)
	}
	oldStrByte, err := json.Marshal(oldStr)
	if err != nil {
		return fmt.Errorf("marshal old ch data failed, %v", err)
	}

	var oldHash, newHash uint64
	h64 := fnv.New64()
	h64.Write(newStrByte)
	newHash = h64.Sum64()
	h64 = fnv.New64()
	h64.Write(oldStrByte)
	oldHash = h64.Sum64()

	if oldHash == newHash {
		return nil
	}

	var t CT
	tableName := reflect.TypeOf(t)
	log.Infof("truncate table %v, old len(%v) hash(%v), new len(%v) hash(%v)", tableName, len(oldItems), oldHash, len(newItems), newHash)
	var deleteItems []*CT
	for _, item := range oldItems {
		deleteItems = append(deleteItems, &item)
	}

	err = mysql.Db.Transaction(func(tx *gorm.DB) error {
		m := new(CT)
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&m).Error; err != nil {
			return fmt.Errorf("truncate table(%s) failed, %v", tableName, err)
		}

		var addItems []CT
		for _, item := range newItems {
			addItems = append(addItems, item)
		}
		if len(addItems) > 0 {
			if err := tx.Create(&addItems).Error; err != nil {
				return fmt.Errorf("add data(len:%d) to table(%s) failed, %v", len(newItems), tableName, err)
			}
		}
		return nil
	})
	return err
}
