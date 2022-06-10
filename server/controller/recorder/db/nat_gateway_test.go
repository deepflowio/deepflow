package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBNATGateway() *mysql.NATGateway {
	return &mysql.NATGateway{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddNATGatewayBatchSuccess() {
	operator := NewNATGateway()
	itemToAdd := newDBNATGateway()

	_, ok := operator.AddBatch([]*mysql.NATGateway{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.NATGateway
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.NATGateway{})
}

func (t *SuiteTest) TestUpdateNATGatewaySuccess() {
	operator := NewNATGateway()
	addedItem := newDBNATGateway()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.NATGateway
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.NATGateway{})
}

func (t *SuiteTest) TestDeleteNATGatewayBatchSuccess() {
	operator := NewNATGateway()
	addedItem := newDBNATGateway()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.NATGateway
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
