package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBPeerConnection() *mysql.PeerConnection {
	return &mysql.PeerConnection{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddPeerConnectionBatchSuccess() {
	operator := NewPeerConnection()
	itemToAdd := newDBPeerConnection()

	_, ok := operator.AddBatch([]*mysql.PeerConnection{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PeerConnection
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PeerConnection{})
}

func (t *SuiteTest) TestUpdatePeerConnectionSuccess() {
	operator := NewPeerConnection()
	addedItem := newDBPeerConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.PeerConnection
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PeerConnection{})
}

func (t *SuiteTest) TestDeletePeerConnectionBatchSuccess() {
	operator := NewPeerConnection()
	addedItem := newDBPeerConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PeerConnection
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
