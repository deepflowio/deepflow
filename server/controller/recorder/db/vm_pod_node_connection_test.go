package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBVMPodNodeConnection() *mysql.VMPodNodeConnection {
	return &mysql.VMPodNodeConnection{Base: mysql.Base{Lcuuid: uuid.New().String()}}
}

func (t *SuiteTest) TestAddVMPodNodeConnectionBatchSuccess() {
	operator := NewVMPodNodeConnection()
	itemToAdd := newDBVMPodNodeConnection()

	_, ok := operator.AddBatch([]*mysql.VMPodNodeConnection{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.VMPodNodeConnection
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VMPodNodeConnection{})
}
