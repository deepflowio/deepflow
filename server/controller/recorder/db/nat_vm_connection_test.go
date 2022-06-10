package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBNATVMConnection() *mysql.NATVMConnection {
	return &mysql.NATVMConnection{Base: mysql.Base{Lcuuid: uuid.New().String()}}
}

func (t *SuiteTest) TestAddNATVMConnectionBatchSuccess() {
	operator := NewNATVMConnection()
	itemToAdd := newDBNATVMConnection()

	_, ok := operator.AddBatch([]*mysql.NATVMConnection{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.NATVMConnection
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.NATVMConnection{})
}

func (t *SuiteTest) TestDeleteNATVMConnectionBatchSuccess() {
	operator := NewNATVMConnection()
	addedItem := newDBNATVMConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.NATVMConnection
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
