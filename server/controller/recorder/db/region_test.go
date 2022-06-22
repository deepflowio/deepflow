package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBRegion() *mysql.Region {
	dbItem := new(mysql.Region)
	dbItem.Lcuuid = uuid.New().String()
	dbItem.Name = uuid.New().String()
	return dbItem
}

func (t *SuiteTest) TestAddRegionBatchSuccess() {
	operator := NewRegion()
	itemToAdd := newDBRegion()

	_, ok := operator.AddBatch([]*mysql.Region{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Region
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Region{})
}

func (t *SuiteTest) TestUpdateRegionSuccess() {
	operator := NewRegion()
	addedItem := newDBRegion()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Region
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Region{})
}

func (t *SuiteTest) TestDeleteRegionSuccess() {
	operator := NewRegion()
	addedItem := newDBRegion()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Region
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
