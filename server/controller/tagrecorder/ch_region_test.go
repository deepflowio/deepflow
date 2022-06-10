package tagrecorder

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBRegion() mysql.Region {
	var region mysql.Region
	region.Lcuuid = uuid.NewString()
	region.Name = region.Lcuuid[:6]
	return region
}

func (t *SuiteTest) TestRefreshChRegion() {
	updater := NewChRegion(
		nil, map[IconKey]int{{NodeType: RESOURCE_TYPE_REGION}: 1},
	)
	region := newDBRegion()
	t.db.Create(&region)
	updater.Refresh()
	var addedItem mysql.ChRegion
	t.db.Where("id = ?", region.ID).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, region.Name)

	region.Name = uuid.NewString()
	t.db.Save(&region)
	updater.Refresh()
	var updatedItem mysql.ChRegion
	t.db.Where("id = ?", region.ID).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, region.Name)

	t.db.Where("id = ?", region.ID).Delete(&mysql.Region{})
	updater.Refresh()
	var deletedItem mysql.ChRegion
	result := t.db.Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Region{})
	t.db.Delete(&mysql.ChRegion{})
}
