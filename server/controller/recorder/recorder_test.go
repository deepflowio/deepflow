/*
 * Copyright (c) 2024 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/test"
	"github.com/deepflowio/deepflow/server/controller/recorder/updater"
)

// const (
// 	TEST_DB_FILE = "./recorder_test.db"
// )

var cloudData []cloudmodel.Resource
var domainLcuuids []string
var domainNames []string
var times int

func BenchmarkAdd(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(2)

	times += 1
	fmt.Printf("第%d次\n", times)
	cfg := config.RecorderConfig{CacheRefreshInterval: 3600}
	for i := 0; i < len(cloudData); i++ {
		recorder := NewRecorder(domainLcuuids[i], domainName[i], cfg, context.Background(), nil)
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
		domain.Name = fmt.Sprintf("第 %d 次性能测试", i)
		mysql.Db.Create(&domain)
		domainLcuuids = append(domainLcuuids, domain.Lcuuid)
		domainNames = append(domainNames, domain.Name)
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

func Test_isPlatformDataChanged(t *testing.T) {
	type args struct {
		updatersInUpdateOrder []updater.ResourceUpdater
	}
	tests := []struct {
		name       string
		args       args
		prepareRun func() []updater.ResourceUpdater
		want       bool
	}{
		{
			name: "pod changed",
			prepareRun: func() []updater.ResourceUpdater {
				cache := cache.NewCache("")
				podUpdater := updater.NewPod(cache, nil)
				podUpdater.Changed = true
				updaters := []updater.ResourceUpdater{
					podUpdater,
					updater.NewPodNode(cache, nil),
				}

				return updaters
			},
			want: true,
		},
		{
			name: "not changed",
			prepareRun: func() []updater.ResourceUpdater {
				cache := cache.NewCache("")
				cenUpdater := updater.NewCEN(cache, nil)
				cenUpdater.Changed = true
				updaters := []updater.ResourceUpdater{
					updater.NewPod(cache, nil),
					cenUpdater,
				}

				return updaters
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.updatersInUpdateOrder = tt.prepareRun()
			if got := isPlatformDataChanged(tt.args.updatersInUpdateOrder); got != tt.want {
				t.Errorf("isPlatformDataChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}
