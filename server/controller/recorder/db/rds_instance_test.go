package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBRDSInstance() *mysql.RDSInstance {
	return &mysql.RDSInstance{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddRDSInstanceBatchSuccess() {
	operator := NewRDSInstance()
	itemToAdd := newDBRDSInstance()

	_, ok := operator.AddBatch([]*mysql.RDSInstance{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.RDSInstance
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RDSInstance{})
}

func (t *SuiteTest) TestUpdateRDSInstanceSuccess() {
	operator := NewRDSInstance()
	addedItem := newDBRDSInstance()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.RDSInstance
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RDSInstance{})
}

func (t *SuiteTest) TestDeleteRDSInstanceBatchSuccess() {
	operator := NewRDSInstance()
	addedItem := newDBRDSInstance()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.RDSInstance
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
