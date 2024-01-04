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

package db

import (
	"math/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func newDBSecurityGroupRule() *mysql.SecurityGroupRule {
	return &mysql.SecurityGroupRule{Base: mysql.Base{Lcuuid: uuid.New().String()}, Priority: rand.Intn(10)}
}

func (t *SuiteTest) TestAddSecurityGroupRuleBatchSuccess() {
	operator := NewSecurityGroupRule()
	itemToAdd := newDBSecurityGroupRule()

	_, ok := operator.AddBatch([]*mysql.SecurityGroupRule{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.SecurityGroupRule
	result := t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SecurityGroupRule{})
}

func (t *SuiteTest) TestUpdateSecurityGroupRuleSuccess() {
	operator := NewSecurityGroupRule()
	addedItem := newDBSecurityGroupRule()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"priority": rand.Intn(10)}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.SecurityGroupRule
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Priority, updateInfo["priority"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SecurityGroupRule{})
}

func (t *SuiteTest) TestDeleteSecurityGroupRuleBatchSuccess() {
	operator := NewSecurityGroupRule()
	addedItem := newDBSecurityGroupRule()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.SecurityGroupRule
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
