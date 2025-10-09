/**
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

package prometheus

import (
	"hash/fnv"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

var (
	versionOnce sync.Once
	version     *Version

	versionName = "prometheus"
)

type Version struct {
	version uint32
	hash    uint64
}

func GetVersion() *Version {
	versionOnce.Do(func() {
		version = &Version{
			version: uint32(time.Now().Unix()),
		}
	})
	return version
}

func (v *Version) Refresh() error {
	versions := "versions"
	if orgIDs, err := metadb.GetORGIDs(); err != nil {
		log.Errorf("failed to get org ids: %v", err)
	} else {
		for _, orgID := range orgIDs {
			db, err := metadb.GetDB(orgID)
			if err != nil {
				log.Errorf("failed to get db: %v for org: %d", err, orgID)
				continue
			}
			var resourceVersion metadbmodel.ResourceVersion
			err = db.Where("name = ?", versionName).First(&resourceVersion).Error
			if err != nil {
				log.Errorf("failed to get version: %v", err, db.LogPrefixORGID)
				continue
			}
			versions += strconv.Itoa(int(resourceVersion.Version))
		}
	}
	curHash := fnv1HashStr(versions)
	if curHash == atomic.LoadUint64(&v.hash) {
		return nil
	}
	atomic.StoreUint64(&v.hash, curHash)
	atomic.StoreUint32(&v.version, uint32(time.Now().Unix()))
	return nil
}

func (v *Version) Get() uint32 {
	v.Refresh()
	return atomic.LoadUint32(&v.version)
}

func fnv1HashStr(s string) uint64 {
	h := fnv.New64()
	h.Write([]byte(s))
	return h.Sum64()
}
