package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func newSecurityGroup() *mysql.SecurityGroup {
	return &mysql.SecurityGroup{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddSecurityGroupBatchSuccess() {
	operator := NewSecurityGroup()
	itemToAdd := newSecurityGroup()

	_, ok := operator.AddBatch([]*mysql.SecurityGroup{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.SecurityGroup
	result := t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SecurityGroup{})
}

func (t *SuiteTest) TestUpdateSecurityGroupSuccess() {
	operator := NewSecurityGroup()
	addedItem := newSecurityGroup()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.SecurityGroup
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SecurityGroup{})

}

func (t *SuiteTest) TestDeleteSecurityGroupBatchSuccess() {
	operator := NewSecurityGroup()
	addedItem := newSecurityGroup()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.SecurityGroup
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
