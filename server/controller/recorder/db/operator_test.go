/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package db

import (
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (t *SuiteTest) TestformatDBItemsToAdd() {
	operator := NewVInterface()
	vifs := []*mysql.VInterface{newDBVInterface(), newDBVInterface()}
	vif1 := vifs[0]
	vif2 := vifs[1]
	vifs = append(vifs, vifs[1])
	mysql.Db.Create(&vif1)
	vif1.ID += 1
	mysql.Db.Create(&vif1)
	vif1.ID += 1
	mysql.Db.Create(&vif1)

	vifsToAdd, lcuuidsToAdd, _, ok := operator.formatItemsToAdd(vifs)
	assert.True(t.T(), ok)
	assert.Equal(t.T(), 1, len(vifsToAdd))
	assert.Equal(t.T(), vif2.Lcuuid, lcuuidsToAdd[0])
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}
