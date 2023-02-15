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
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/test"
)

// const (
// 	TEST_DB_FILE = "./recorder_test.db"
// )

var cloudData []cloudmodel.Resource
var domainLcuuids []string
var times int

func BenchmarkAdd(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(2)

	times += 1
	fmt.Printf("第%d次\n", times)
	cfg := config.RecorderConfig{CacheRefreshInterval: 3600}
	for i := 0; i < len(cloudData); i++ {
		recorder := NewRecorder(domainLcuuids[i], cfg, context.Background(), nil)
		recorder.Start()
		time.Sleep(time.Second * 1)
		recorder.Refresh(cloudData[i])

	LOOP:
		for {
			select {
			case <-recorder.canRefresh:
				break LOOP
			}
		}
	}
}

func TestMain(m *testing.M) {
	clearDBFile()
	mysql.Db = test.GetDB(TEST_DB_FILE)
	for _, val := range test.GetModels() {
		mysql.Db.AutoMigrate(val)
	}

	for i := 0; i < 1; i++ {
		domain := new(mysql.Domain)
		domain.Lcuuid = uuid.NewString()
		domain.Name = "性能测试"
		mysql.Db.Create(&domain)
		domainLcuuids = append(domainLcuuids, domain.Lcuuid)
		cloudData = append(cloudData, test.NewCloudResource(1))
	}
	publicNetwork := new(mysql.Network)
	publicNetwork.Lcuuid = rcommon.PUBLIC_NETWORK_LCUUID
	mysql.Db.Create(&publicNetwork)

	exitCode := m.Run()

	sqlDB, _ := mysql.Db.DB()
	defer sqlDB.Close()
	clearDBFile()
	os.Exit(exitCode)
}

func clearDBFile() {
	if _, err := os.Stat(TEST_DB_FILE); err == nil {
		os.Remove(TEST_DB_FILE)
	}
}
