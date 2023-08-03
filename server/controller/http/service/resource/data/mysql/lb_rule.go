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
	"strings"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"golang.org/x/exp/slices"
)

type LBRule struct {
	DataProvider
	dataTool *lbRuleToolData
}

func NewLBRule() *LBRule {
	dp := &LBRule{newDataProvider(ctrlrcommon.RESOURCE_TYPE_LB_RULE_EN), new(lbRuleToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *LBRule) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.lbTargetServers {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *LBRule) generateOne(item mysql.LBTargetServer) common.ResponseElem {
	d := make(common.ResponseElem)
	lb := v.dataTool.idToLB[item.LBID]
	lbListener := v.dataTool.idToLBListener[item.LBListenerID]
	d["EPC_ID"] = float64(lb.VPCID)
	d["LB_ID"] = float64(lb.ID)
	d["LB_NAME"] = lb.Name
	d["LB_MODEL"] = lb.Model
	d["LISTENER_ID"] = float64(lbListener.ID)
	d["LISTENER_NAME"] = lbListener.Name
	d["LISTEN_IP"] = lbListener.IPs
	snatIPs := make([]string, 0)
	if lbListener.SNATIPs != "" {
		snatIPs = strings.Split(lbListener.SNATIPs, ",")
	}
	d["LISTEN_SNAT_IPS"] = snatIPs
	d["LISTEN_PROTOCOL"] = lbListener.Protocol
	d["LISTEN_PORT"] = lbListener.Port
	d["DEST_VM_ID"] = item.VMID
	d["DEST_VM_NAME"] = v.dataTool.vmIDToName[item.VMID]
	d["DEST_IP"] = item.IP
	d["DEST_PROTOCOL"] = item.Protocol
	d["DEST_PORT"] = item.Port
	return d
}

type lbRuleToolData struct {
	lbTargetServers []mysql.LBTargetServer

	idToLB         map[int]mysql.LB
	idToLBListener map[int]mysql.LBListener

	vmIDToName map[int]string
}

func (td *lbRuleToolData) Init() *lbRuleToolData {
	td.idToLB = make(map[int]mysql.LB)
	td.idToLBListener = make(map[int]mysql.LBListener)

	td.vmIDToName = make(map[int]string)
	return td
}

func (td *lbRuleToolData) Load() (err error) {
	td.lbTargetServers, err = GetAll[mysql.LBTargetServer]()
	if err != nil {
		return err
	}

	vmIDs := make([]int, 0)
	for _, item := range td.lbTargetServers {
		if item.VMID != 0 && !slices.Contains(vmIDs, item.VMID) {
			vmIDs = append(vmIDs, item.VMID)
		}
	}
	vms, err := SelectWithQuery[mysql.VM]([]string{"id", "name"}, "id IN (?)", vmIDs)
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.vmIDToName[item.ID] = item.Name
	}

	lbs, err := Select[mysql.LB]([]string{"id", "name", "epc_id", "model"})
	if err != nil {
		return err
	}
	for _, item := range lbs {
		td.idToLB[item.ID] = item
	}

	lbListeners, err := GetAll[mysql.LBListener]()
	if err != nil {
		return err
	}
	for _, item := range lbListeners {
		td.idToLBListener[item.ID] = item
	}
	return nil
}
