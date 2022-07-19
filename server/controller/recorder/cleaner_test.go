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

package recorder

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/test"
)

func TestDelete(t *testing.T) {
	clearDBFile()
	mysql.Db = test.GetDB(TEST_DB_FILE)
	vm := mysql.VM{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
	mysql.Db.Create(&vm)
	mysql.Db.Model(mysql.VM{}).Where("lcuuid = ?", vm.Lcuuid).Updates(map[string]interface{}{"deleted_at": time.Now().Add(time.Duration(-24) * time.Hour)})
	var addedVM mysql.VM
	mysql.Db.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID == 0 {
		fmt.Println("addedVM should not be null")
	}
	delete[mysql.VM](time.Now().Add(time.Duration(-1) * time.Hour))
	mysql.Db.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID != 0 {
		fmt.Println("addedVM should be null")
	}
	clearDBFile()
}
