package updater

import (
	"reflect"
	"strconv"

	"bou.ke/monkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
)

func newCloudCEN() cloudmodel.CEN {
	lcuuid := uuid.New().String()
	return cloudmodel.CEN{
		Lcuuid:     lcuuid,
		Name:       lcuuid[:8],
		VPCLcuuids: []string{uuid.NewString()},
	}
}

func (t *SuiteTest) getCENMock(mockDB bool) (*cache.Cache, cloudmodel.CEN) {
	cloudItem := newCloudCEN()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.CEN{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.CENs[cloudItem.Lcuuid] = &cache.CEN{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddCENSucess() {
	cache_, cloudItem := t.getCENMock(false)
	vpcID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return vpcID, true
	})
	assert.Equal(t.T(), len(cache_.CENs), 0)

	updater := NewCEN(cache_, []cloudmodel.CEN{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid")

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.CENs), 1)
	assert.Equal(t.T(), addedItem.VPCIDs, strconv.Itoa(vpcID))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestHandleUpdateCENSucess() {
	cache, cloudItem := t.getCENMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewCEN(cache, []cloudmodel.CEN{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), len(cache.CENs), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestHandleDeleteCENSucess() {
	cache, cloudItem := t.getCENMock(true)

	updater := NewCEN(cache, []cloudmodel.CEN{})
	updater.HandleDelete()

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.CENs), 0)
}
