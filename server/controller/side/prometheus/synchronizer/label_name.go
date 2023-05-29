/**
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

package synchronizer

import (
	"errors"
	"sort"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type labelName struct {
	mutex        sync.Mutex
	resourceType string
	Max          int
	usableIDs    []int
	strToID      map[string]int
}

func newLabelName(max int) *labelName {
	return &labelName{
		resourceType: "metric_name",
		Max:          max,
		usableIDs:    make([]int, 0, max),
		strToID:      make(map[string]int),
	}
}

func (p *labelName) load() (ids mapset.Set[int], err error) {
	var items []mysql.PrometheusLabelName
	err = mysql.Db.Unscoped().Select("id").Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", p.resourceType, err)
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(item.ID)
		p.strToID[item.Name] = item.ID
	}
	return inUseIDsSet, nil
}

func (p *labelName) refresh(args ...interface{}) error {
	log.Infof("refresh %s id pools started", p.resourceType)
	inUseIDsSet, err := p.load()
	if err != nil {
		return err
	}
	allIDsSet := mapset.NewSet[int]()
	for i := 1; i <= p.Max; i++ {
		allIDsSet.Add(i)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()
	// 可用ID = 所有ID（1~max）- db中正在使用的ID
	// 排序原则：大于db正在使用的max值的ID（未曾被使用过的ID）优先，小于db正在使用的max值的ID（已被使用过且已回收的ID）在后
	var usableIDs []int
	if inUseIDsSet.Cardinality() != 0 {
		inUseIDs := inUseIDsSet.ToSlice()
		sort.IntSlice(inUseIDs).Sort()
		maxInUseID := inUseIDs[len(inUseIDs)-1]

		usableIDsSet := allIDsSet.Difference(inUseIDsSet)
		usedIDs := []int{}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		for _, id := range usableIDs {
			if id < maxInUseID {
				usedIDs = append(usedIDs, id)
				usableIDsSet.Remove(id)
			} else {
				break
			}
		}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		sort.IntSlice(usedIDs).Sort()
		usableIDs = append(usableIDs, usedIDs...)
	} else {
		usableIDs = allIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
	}
	p.usableIDs = usableIDs

	log.Infof("refresh %s id pools (usable ids count: %d) completed", p.resourceType, len(p.usableIDs))
	return nil
}

// 批量分配ID，若ID池中数量不足，分配ID池所有ID；反之分配指定个数ID。
// 分配的ID中，若已有被实际使用的ID（闭源页面创建使用），排除已使用ID，仅分配剩余部分。
func (p *labelName) allocate(count int) (ids []int, err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.usableIDs) == 0 {
		log.Errorf("%s has no more usable ids", p.resourceType)
		return
	}

	if len(p.usableIDs) < count {
		return nil, errors.New("no more usable ids")
	}
	ids = make([]int, count)
	copy(ids, p.usableIDs[:count])

	inUseIDs, err := p.check(ids)
	if err != nil {
		return
	}
	if len(inUseIDs) != 0 {
		return nil, errors.New("some ids are in use")
	}
	log.Infof("allocate %s ids: %v (expected count: %d, true count: %d)", p.resourceType, ids, count, len(ids))
	p.usableIDs = p.usableIDs[count:]
	return
}

func (p *labelName) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []mysql.PrometheusLabelName
	err = mysql.Db.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", p.resourceType, err)
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, item.ID)
		}
		log.Infof("%s ids: %+v are in use.", p.resourceType, inUseIDs)
	}
	return
}

func (p *labelName) sync(strs []string) ([]*controller.PrometheusLabelName, error) {
	resp := make([]*controller.PrometheusLabelName, 0)
	dbToAdd := make([]*mysql.PrometheusLabelName, 0)
	var countToAllocate int
	for _, str := range strs {
		if _, ok := p.strToID[str]; !ok {
			countToAllocate++
			dbToAdd = append(dbToAdd, &mysql.PrometheusLabelName{Name: str})
			continue
		}
		resp = append(resp, &controller.PrometheusLabelName{Name: &str, Id: proto.Uint32(uint32(p.strToID[str]))})
	}
	if countToAllocate == 0 {
		return resp, nil
	}
	ids, err := p.allocate(countToAllocate)
	if err != nil {
		return nil, err
	}
	for i := range dbToAdd {
		dbToAdd[i].ID = ids[i]
		resp = append(resp, &controller.PrometheusLabelName{Name: &dbToAdd[i].Name, Id: proto.Uint32(uint32(dbToAdd[i].ID))})
	}
	err = p.addBatch(dbToAdd)
	if err != nil {
		return nil, err
	}
	for _, item := range dbToAdd {
		p.strToID[item.Name] = item.ID
	}
	return resp, nil
}

func (p *labelName) addBatch(toAdd []*mysql.PrometheusLabelName) error {
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		oneP := toAdd[start:end]
		err := mysql.Db.Create(&oneP).Error
		if err != nil {
			return err
		}
		log.Infof("add %d labels success", len(oneP))
	}
	return nil
}
