package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func newDBVInterface() *mysql.VInterface {
	return &mysql.VInterface{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String(), Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddVInterfaceBatchSuccess() {
	operator := NewVInterface()
	itemToAdd := newDBVInterface()

	_, ok := operator.AddBatch([]*mysql.VInterface{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.VInterface
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}

func (t *SuiteTest) TestUpdateVInterfaceSuccess() {
	operator := NewVInterface()
	addedItem := newDBVInterface()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.VInterface
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}

func (t *SuiteTest) TestDeleteVInterfaceBatchSuccess() {
	operator := NewVInterface()
	addedItem := newDBVInterface()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.VInterface
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
