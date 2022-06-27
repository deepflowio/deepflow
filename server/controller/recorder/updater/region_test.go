package updater

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
)

func newCloudRegion() cloudmodel.Region {
	lcuuid := uuid.New().String()
	return cloudmodel.Region{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		Label:  lcuuid[:6],
	}
}

func (t *SuiteTest) getRegionMock(mockDB bool) (*cache.Cache, cloudmodel.Region) {
	cloudItem := newCloudRegion()

	domainLcuuid := uuid.New().String()
	wholeCache := cache.NewCache(domainLcuuid)

	if mockDB {
		dbItem := new(mysql.Region)
		dbItem.Lcuuid = cloudItem.Lcuuid
		dbItem.Name = cloudItem.Name
		t.db.Create(dbItem)
		wholeCache.Regions[cloudItem.Lcuuid] = &cache.Region{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	wholeCache.SetSequence(wholeCache.GetSequence() + 1)

	return wholeCache, cloudItem
}

func (t *SuiteTest) TestHandleAddRegionSucess() {
	cache, cloudItem := t.getRegionMock(false)

	updater := NewRegion(cache, []cloudmodel.Region{cloudItem})
	updater.HandleAddAndUpdate()
	var addedItem *mysql.Region
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}

func (t *SuiteTest) TestHandleUpdateRegionSucess() {
	cache, cloudItem := t.getRegionMock(true)
	cloudItem.Label = cloudItem.Label + "new"

	updater := NewRegion(cache, []cloudmodel.Region{cloudItem})
	updater.HandleAddAndUpdate()
	var updatedItem *mysql.Region
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), updatedItem.Label, cloudItem.Label)
	assert.Equal(t.T(), cache.Regions[cloudItem.Lcuuid].Label, cloudItem.Label)

	diffBase := cache.Regions[cloudItem.Lcuuid]
	assert.Equal(t.T(), diffBase.GetSequence(), cache.GetSequence())

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}

func (t *SuiteTest) TestHandleDeleteRegionSuccess() {
	cache, cloudItem := t.getRegionMock(true)

	updater := NewRegion(cache, []cloudmodel.Region{})
	updater.HandleAddAndUpdate()
	updater.HandleDelete()
	var deletedItem *mysql.Region
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}
