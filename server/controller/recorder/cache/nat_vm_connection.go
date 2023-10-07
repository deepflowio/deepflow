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

package cache

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DiffBaseDataSet) addNATVMConnection(dbItem *mysql.NATVMConnection, seq int) {
	b.NATVMConnections[dbItem.Lcuuid] = &NATVMConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, b.NATVMConnections[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNATVMConnection(lcuuid string) {
	delete(b.NATVMConnections, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, lcuuid))
}

type NATVMConnection struct {
	DiffBase
}
