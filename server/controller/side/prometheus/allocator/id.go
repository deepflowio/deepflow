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

package allocator

import (
	"errors"
	"sort"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/constraint"
)

type StrID struct {
	ID  int
	Str string
}

type idPoolUpdater interface {
	refresh() error
	allocate(strs []string) ([]StrID, error)
}

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type idPool[MT MySQLModel] struct {
	mutex        sync.Mutex
	ResourceType string
	Max          int
	usableIDs    []int
	strToID      map[string]int
}

func (p *idPool[MT]) refresh() error {
	log.Infof("refresh %s id pools started", p.ResourceType)

	var items []*MT
	err := mysql.Db.Unscoped().Select("id").Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", p.ResourceType, err)
		return err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		id := (*item).GetID()
		inUseIDsSet.Add(id)
		p.strToID[(*item).GetStr()] = id
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

	log.Infof("refresh %s id pools (usable ids count: %d) completed", p.ResourceType, len(p.usableIDs))
	return nil
}

// 批量分配ID，若ID池中数量不足，分配ID池所有ID；反之分配指定个数ID。
// 分配的ID中，若已有被实际使用的ID（闭源页面创建使用），排除已使用ID，仅分配剩余部分。
func (p *idPool[MT]) allocate(strs []string) ([]StrID, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	strIDs := make([]StrID, 0)
	strsNeedEncode := make([]string, 0)
	for _, str := range strs {
		if id, ok := p.strToID[str]; ok {
			strIDs = append(strIDs, StrID{ID: id, Str: str})
		} else {
			strsNeedEncode = append(strsNeedEncode, str)
		}
	}

	if len(strsNeedEncode) == 0 {
		return strIDs, nil
	}

	if len(p.usableIDs) == 0 {
		log.Errorf("%s has no more usable ids", p.ResourceType)
		return nil, errors.New("no more usable ids") // TODO use error code
	}

	if len(strsNeedEncode) > len(p.usableIDs) {
		log.Errorf("%s has no enough usable ids", p.ResourceType)
		return nil, errors.New("no enough usable ids")
	}

	count := len(strsNeedEncode)
	ids := make([]int, count)
	copy(ids, p.usableIDs[:count])
	p.usableIDs = p.usableIDs[count:]

	var dbItems []*MT
	err := mysql.Db.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", p.ResourceType, err)
		return nil, err
	}
	if len(dbItems) != 0 {
		inUseIDs := make([]int, 0, len(dbItems))
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, (*item).GetID())
		}
		log.Errorf("%s ids: %+v are in use.", p.ResourceType, inUseIDs)
		return nil, errors.New("allocated ids are in use, try again")
	}
	log.Infof("allocate %s str ids: %v", p.ResourceType, ids)

	for i, id := range ids {
		p.strToID[strsNeedEncode[i]] = id
		strIDs = append(strIDs, StrID{ID: id, Str: strsNeedEncode[i]})
	}
	return strIDs, err
}
