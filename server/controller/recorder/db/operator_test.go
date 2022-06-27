package db

import (
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func (t *SuiteTest) TestformatDBItemsToAdd() {
	operator := NewVInterface()
	vifs := []*mysql.VInterface{newDBVInterface(), newDBVInterface()}
	vif1 := vifs[0]
	vif2 := vifs[1]
	mysql.Db.Create(&vif1)

	vifsToAdd, lcuuidsToAdd, ok := operator.formatDBItemsToAdd(vifs)
	assert.True(t.T(), ok)
	assert.Equal(t.T(), 1, len(vifsToAdd))
	assert.Equal(t.T(), vif2.Lcuuid, lcuuidsToAdd[0])
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}
