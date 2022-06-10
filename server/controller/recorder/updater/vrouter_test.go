package updater

import (
	"fmt"
	"reflect"

	"bou.ke/monkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
)

func newCloudVRouter() cloudmodel.VRouter {
	lcuuid := uuid.New().String()
	return cloudmodel.VRouter{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
	}
}

func (t *SuiteTest) getVRouterMock(mockDB bool) (*cache.Cache, cloudmodel.VRouter) {
	cloudItem := newCloudVRouter()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.VRouter{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.VRouters[cloudItem.Lcuuid] = &cache.VRouter{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddVRouterSucess() {
	cache_, cloudItem := t.getVRouterMock(false)
	vpcID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return vpcID, true
	})
	assert.Equal(t.T(), len(cache_.VRouters), 0)

	updater := NewVRouter(cache_, []cloudmodel.VRouter{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(cache_), "GetVPCIDByLcuuid")

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.VRouters), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestHandleUpdateVRouterSucess() {
	cache_, cloudItem := t.getVRouterMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.VPCLcuuid = uuid.NewString()
	newVPCID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return newVPCID, true
	})

	updater := NewVRouter(cache_, []cloudmodel.VRouter{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid")

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.VRouters), 1)
	fmt.Println(addedItem)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), addedItem.VPCID, newVPCID)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestHandleDeleteVRouterSucess() {
	cache, cloudItem := t.getVRouterMock(true)

	updater := NewVRouter(cache, []cloudmodel.VRouter{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.VRouters), 0)
}
