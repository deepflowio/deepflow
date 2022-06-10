package recorder

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"server/controller/db/mysql"
	"server/controller/recorder/test"
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
