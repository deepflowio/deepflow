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

package mysql

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type LBListener struct {
	DataProvider
	dataTool *lbListenerToolData
}

func NewLBListener() *LBListener {
	dp := &LBListener{newDataProvider(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN), new(lbListenerToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *LBListener) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.lbListeners {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *LBListener) generateOne(item mysql.LBListener) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["EPC_ID"] = float64(v.dataTool.lbIDToVPCID[item.LBID])

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type lbListenerToolData struct {
	lbListeners []mysql.LBListener

	lbIDToVPCID map[int]int
}

func (td *lbListenerToolData) Init() *lbListenerToolData {
	td.lbIDToVPCID = make(map[int]int)
	return td
}

func (td *lbListenerToolData) Load() (err error) {
	td.lbListeners, err = GetAll[mysql.LBListener]()
	if err != nil {
		return err
	}

	lbs, err := Select[mysql.LB]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range lbs {
		td.lbIDToVPCID[item.ID] = item.VPCID
	}
	return nil
}
