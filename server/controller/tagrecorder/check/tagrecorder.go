/*
 * Copyright (c) 2023 Yunshan Networks
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

package tagrecorder

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"
	"sync"
	"time"

	logging "github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var (
	log = logging.MustGetLogger("tagrecorder/check")

	tagRecorderOnce sync.Once
	tagRecorder     *TagRecorder
)

func GetSingleton() *TagRecorder {
	tagRecorderOnce.Do(func() {
		tagRecorder = &TagRecorder{}
	})
	return tagRecorder
}

func (c *TagRecorder) Init(ctx context.Context, cfg config.ControllerConfig) {
	c.cfg = cfg
	tCtx, tCancel := context.WithCancel(ctx)
	c.tCtx = tCtx
	c.tCancel = tCancel
}

type TagRecorder struct {
	tCtx    context.Context
	tCancel context.CancelFunc
	cfg     config.ControllerConfig
}

func (c *TagRecorder) Check() {
	go func() {
		log.Info("tagrecorder health check data run")
		t := time.Now()
		if err := mysql.GetDBs().DoOnAllDBs(func(db *mysql.DB) error {
			return c.check(db)
		}); err != nil {
			log.Error(err)
		}
		log.Infof("tagrecorder health check data end, time since: %v", time.Since(t))
	}()
}

func (c *TagRecorder) check(db *mysql.DB) error {
	// 调用API获取资源对应的icon_id
	domainToIconID, resourceToIconID, _ := c.UpdateIconInfo(db)
	for _, updater := range c.getUpdaters(db, domainToIconID, resourceToIconID) {
		if err := updater.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (t *TagRecorder) Stop() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Info("tagrecorder stopped")
}

func (c *TagRecorder) getUpdaters(db *mysql.DB, domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) []ChResourceUpdater {
	// 生成各资源更新器，刷新ch数据
	updaters := []ChResourceUpdater{
		// NewChRegion(domainLcuuidToIconID, resourceTypeToIconID),
		NewChAZ(domainLcuuidToIconID, resourceTypeToIconID),
		NewChVPC(resourceTypeToIconID),
		NewChDevice(resourceTypeToIconID),
		// NewChIPRelation(),
		NewChPodK8sLabel(),
		NewChPodK8sLabels(),
		NewChPodServiceK8sLabel(),
		NewChPodServiceK8sLabels(),
		NewChChostCloudTag(),
		NewChPodNSCloudTag(),
		NewChChostCloudTags(),
		NewChPodNSCloudTags(),
		NewChOSAppTag(),
		NewChOSAppTags(),
		// NewChVTapPort(),
		NewChStringEnum(),
		NewChIntEnum(),
		// NewChNodeType(),
		// NewChAPPLabel(),
		// NewChTargetLabel(),
		// NewChPrometheusTargetLabelLayout(),
		// NewChPrometheusLabelName(),
		// NewChPrometheusMetricNames(),
		// NewChPrometheusMetricAPPLabelLayout(),
		NewChNetwork(resourceTypeToIconID),
		// NewChTapType(resourceTypeToIconID),
		// NewChVTap(resourceTypeToIconID),
		NewChPod(resourceTypeToIconID),
		NewChPodCluster(resourceTypeToIconID),
		NewChPodGroup(resourceTypeToIconID),
		NewChPodNamespace(resourceTypeToIconID),
		NewChPodNode(resourceTypeToIconID),
		// NewChLbListener(resourceTypeToIconID),
		NewChPodIngress(resourceTypeToIconID),
		NewChGProcess(resourceTypeToIconID),

		NewChPodK8sAnnotation(),
		NewChPodK8sAnnotations(),
		NewChPodServiceK8sAnnotation(),
		NewChPodServiceK8sAnnotations(),
		NewChPodK8sEnv(),
		NewChPodK8sEnvs(),
		NewChPodService(),
		NewChChost(),

		// NewChPolicy(),
		// NewChNpbTunnel(),
	}
	if c.cfg.RedisCfg.Enabled {
		updaters = append(updaters, NewChIPResource(c.tCtx))
	}
	for _, updater := range updaters {
		updater.SetConfig(c.cfg)
		updater.SetDB(db)
	}
	return updaters
}

func (b *UpdaterBase[MT, KT]) Check() error {
	newItemMap, newOK := b.dataGenerator.generateNewData()
	oldItems, oldOK := b.generateOldData()
	if !oldOK {
		return fmt.Errorf("failed to get new data")
	}
	if !newOK {
		return fmt.Errorf("failed to get old data")
	}
	newItems := make([]MT, len(newItemMap))
	i := 0
	for _, item := range newItemMap {
		newItems[i] = item
		i++
	}

	return compareAndCheck(b.db, oldItems, newItems)
}

func compareAndCheck[CT MySQLChModel](db *mysql.DB, oldItems, newItems []CT) error {
	if len(newItems) == 0 && len(oldItems) == 0 {
		return nil
	}

	oldHash, newHash, err := genH64(oldItems, newItems)
	if err != nil {
		return err
	}
	var t CT
	tableName := reflect.TypeOf(t)
	log.Infof("check tagrecorder table(%v), old len(%v) hash(%v), new len(%v) hash(%v)", tableName, len(oldItems), oldHash, len(newItems), newHash)
	if oldHash == newHash {
		return nil
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		m := new(CT)
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&m).Error; err != nil {
			return fmt.Errorf("truncate table(%s) failed, %v", tableName, err)
		}

		var addItems []CT
		for _, item := range newItems {
			addItems = append(addItems, item)
		}
		if len(addItems) > 0 {
			if err := tx.Create(&addItems).Error; err != nil {
				return fmt.Errorf("add data(len:%d) to table(%s) failed, %v", len(newItems), tableName, err)
			}
		}
		return nil
	})
	log.Infof("truncate table(%v)", tableName)
	return err
}

func genH64[CT MySQLChModel](oldItems, newItems []CT) (oldHash, newHash uint64, err error) {
	var newStrByte []byte
	newStr := make([]string, len(newItems))
	for i, item := range newItems {
		newStrByte, err = json.Marshal(item)
		if err != nil {
			err = fmt.Errorf("marshal new ch data failed, %v", err)
			return
		}
		newStr[i] = string(newStrByte)
	}
	sort.Strings(newStr)
	newData, err := json.Marshal(newStr)
	if err != nil {
		return
	}

	var oldStrByte []byte
	oldStr := make([]string, len(oldItems))
	for i, item := range oldItems {
		oldStrByte, err = json.Marshal(item)
		if err != nil {
			err = fmt.Errorf("marshal old ch data failed, %v", err)
			return
		}
		oldStr[i] = string(oldStrByte)
	}
	sort.Strings(oldStr)
	oldData, err := json.Marshal(oldStr)
	if err != nil {
		return
	}

	h64 := fnv.New64()
	h64.Write(newData)
	newHash = h64.Sum64()
	h64 = fnv.New64()
	h64.Write(oldData)
	oldHash = h64.Sum64()
	return
}
