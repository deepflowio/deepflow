package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBLBVMCConnection() *mysql.LBVMConnection {
	return &mysql.LBVMConnection{Base: mysql.Base{Lcuuid: uuid.New().String()}}
}

func (t *SuiteTest) TestAddLBVMCConnectionBatchSuccess() {
	operator := NewLBVMConnection()
	itemToAdd := newDBLBVMCConnection()

	_, ok := operator.AddBatch([]*mysql.LBVMConnection{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.LBVMConnection
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LBVMConnection{})
}

func (t *SuiteTest) TestDeleteLBVMCConnectionBatchSuccess() {
	operator := NewLBVMConnection()
	addedItem := newDBLBVMCConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.LBVMConnection
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
