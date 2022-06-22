package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBVRouter() *mysql.VRouter {
	return &mysql.VRouter{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddVRouterBatchSuccess() {
	operator := NewVRouter()
	itemToAdd := newDBVRouter()

	_, ok := operator.AddBatch([]*mysql.VRouter{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.VRouter
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestUpdateVRouterSuccess() {
	operator := NewVRouter()
	addedItem := newDBVRouter()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String(), "epc_id": 123}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.VRouter
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])
	assert.Equal(t.T(), updatedItem.VPCID, 123)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestDeleteVRouterBatchSuccess() {
	operator := NewVRouter()
	addedItem := newDBVRouter()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.VRouter
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
