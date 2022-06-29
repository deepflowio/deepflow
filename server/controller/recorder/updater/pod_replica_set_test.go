package updater

import (
	"reflect"

	"bou.ke/monkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/test"
)

func newCloudPodReplicaSet() cloudmodel.PodReplicaSet {
	lcuuid := uuid.New().String()
	return cloudmodel.PodReplicaSet{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		Label:  lcuuid[:6],
	}
}

func (t *SuiteTest) getPodReplicaSetMock(mockDB bool) (*cache.Cache, cloudmodel.PodReplicaSet) {
	cloudItem := newCloudPodReplicaSet()
	domainLcuuid := uuid.New().String()

	c := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.PodReplicaSet{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid, Label: cloudItem.Label})
		c.PodReplicaSets[cloudItem.Lcuuid] = &cache.PodReplicaSet{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name, Label: cloudItem.Label}
	}

	c.SetSequence(c.GetSequence() + 1)

	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddPodReplicaSetSucess() {
	c, cloudItem := t.getPodReplicaSetMock(false)
	assert.Equal(t.T(), len(c.PodReplicaSets), 0)
	podNamespaceID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNamespaceIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podNamespaceID, true
	})
	podClusterID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodClusterIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podClusterID, true
	})
	podGroupID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodGroupIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podGroupID, true
	})

	updater := NewPodReplicaSet(c, []cloudmodel.PodReplicaSet{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNamespaceIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodClusterIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodGroupIDByLcuuid")

	var addedItem *mysql.PodReplicaSet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(c.PodReplicaSets), 1)
	assert.Equal(t.T(), cloudItem.Label, addedItem.Label)

	test.ClearDBData[mysql.PodReplicaSet](t.db)
}

func (t *SuiteTest) TestHandleUpdatePodReplicaSetSucess() {
	cache, cloudItem := t.getPodReplicaSetMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.Label = cloudItem.Label + "new"

	updater := NewPodReplicaSet(cache, []cloudmodel.PodReplicaSet{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.PodReplicaSet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.PodReplicaSets), 1)
	assert.Equal(t.T(), addedItem.Label, cloudItem.Label)

	test.ClearDBData[mysql.PodReplicaSet](t.db)
}
