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

package vtap

import (
	"context"
	"fmt"
	"regexp"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var log = logging.MustGetLogger("monitor/vtap")

type VTapCheck struct {
	vCtx    context.Context
	vCancel context.CancelFunc
	cfg     config.MonitorConfig
}

func NewVTapCheck(cfg config.MonitorConfig, ctx context.Context) *VTapCheck {
	vCtx, vCancel := context.WithCancel(ctx)
	return &VTapCheck{
		vCtx:    vCtx,
		vCancel: vCancel,
		cfg:     cfg,
	}
}

func (v *VTapCheck) Start() {
	log.Info("controller check start")
	go func() {
		for range time.Tick(time.Duration(v.cfg.VTapCheckInterval) * time.Second) {
			mysql.GetDBs().DoOnAllDBs(func(db *mysql.DB) error {
				// check launch_server resource if exist
				v.launchServerCheck(db)
				// check vtap type
				v.typeCheck(db)
				return nil
			})
		}
	}()

	go func() {
		for range time.Tick(time.Second * time.Duration(v.cfg.VTapAutoDeleteInterval)) {
			mysql.GetDBs().DoOnAllDBs(func(db *mysql.DB) error {
				v.deleteLostVTap(db)
				return nil
			})
		}
	}()
}

func (v *VTapCheck) Stop() {
	if v.vCancel != nil {
		v.vCancel()
	}
	log.Info("vtap check stopped")
}

func (v *VTapCheck) launchServerCheck(db *mysql.DB) {
	var vtaps []mysql.VTap
	var reg = regexp.MustCompile(` |:`)

	log.Debugf("ORG(id=%d database=%s) vtap launch_server check start", db.ORGID, db.Name)

	db.Find(&vtaps)
	for _, vtap := range vtaps {
		switch vtap.Type {
		case common.VTAP_TYPE_WORKLOAD_V:
			var vm mysql.VM
			if ret := db.Where("lcuuid = ?", vtap.Lcuuid).First(&vm); ret.Error != nil {
				log.Infof("ORG(id=%d database=%s) delete vtap: %s %s, because no related vm", db.ORGID, db.Name, vtap.Name, vtap.Lcuuid)
				db.Delete(&vtap)
			} else {
				vtapName := reg.ReplaceAllString(fmt.Sprintf("%s-W%d", vm.Name, vm.ID), "-")
				// check and update name
				if vtap.Name != vtapName {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) name from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Name, vtapName,
					)
					db.Model(&vtap).Update("name", vtapName)
				}
				// check and update launch_server_id
				if vtap.LaunchServerID != vm.ID {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) launch_server_id from %d to %d",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.LaunchServerID, vm.ID,
					)
					db.Model(&vtap).Update("launch_server_id", vm.ID)
				}
				// check and update region
				if vtap.Region != vm.Region {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) region from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Region, vm.Region,
					)
					db.Model(&vtap).Update("region", vm.Region)
				}
			}

		case common.VTAP_TYPE_KVM, common.VTAP_TYPE_ESXI, common.VTAP_TYPE_HYPER_V:
			var host mysql.Host
			if ret := db.Where("ip = ?", vtap.LaunchServer).First(&host); ret.Error != nil {
				log.Infof("delete vtap: %s %s", vtap.Name, vtap.Lcuuid)
				db.Delete(&vtap)
			} else {
				vtapName := reg.ReplaceAllString(fmt.Sprintf("%s-H%d", host.Name, host.ID), "-")
				// check and update name
				if vtap.Name != vtapName {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) name from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Name, vtapName,
					)
					db.Model(&vtap).Update("name", vtapName)
				}
				// check and update launch_server_id
				if vtap.LaunchServerID != host.ID {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) launch_server_id from %d to %d",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.LaunchServerID, host.ID,
					)
					db.Model(&vtap).Update("launch_server_id", host.ID)
				}
				// check and update region
				if vtap.Region != host.Region {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) region from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Region, host.Region,
					)
					db.Model(&vtap).Update("region", host.Region)
				}
			}
		case common.VTAP_TYPE_POD_HOST, common.VTAP_TYPE_POD_VM:
			var podNode mysql.PodNode
			if ret := db.Where("lcuuid = ?", vtap.Lcuuid).First(&podNode); ret.Error != nil {
				log.Infof("ORG(id=%d database=%s) delete vtap: %s %s", db.ORGID, db.Name, vtap.Name, vtap.Lcuuid)
				db.Delete(&vtap)
			} else {
				var vtapName string
				if vtap.Type == common.VTAP_TYPE_POD_HOST {
					vtapName = reg.ReplaceAllString(fmt.Sprintf("%s-P%d", podNode.Name, podNode.ID), "-")
				} else {
					vtapName = reg.ReplaceAllString(fmt.Sprintf("%s-V%d", podNode.Name, podNode.ID), "-")
				}
				// check and update name
				if vtap.Name != vtapName {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) name from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Name, vtapName,
					)
					db.Model(&vtap).Update("name", vtapName)
				}
				// check and update launch_server_id
				if vtap.LaunchServerID != podNode.ID {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) launch_server_id from %d to %d",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.LaunchServerID, podNode.ID,
					)
					db.Model(&vtap).Update("launch_server_id", podNode.ID)
				}
				// check and update region
				if vtap.Region != podNode.Region {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) region from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Region, podNode.Region,
					)
					db.Model(&vtap).Update("region", podNode.Region)
				}
			}
		case common.VTAP_TYPE_K8S_SIDECAR:
			var pod mysql.Pod
			if ret := db.Where("lcuuid = ?", vtap.Lcuuid).First(&pod); ret.Error != nil {
				log.Infof("ORG(id=%d database=%s) delete vtap: %s %s", db.ORGID, db.Name, vtap.Name, vtap.Lcuuid)
				db.Delete(&vtap)
			} else {
				vtapName := reg.ReplaceAllString(fmt.Sprintf("%s-P%d", pod.Name, pod.ID), "-")
				// check and update name
				if vtap.Name != vtapName {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) name from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Name, vtapName,
					)
					db.Model(&vtap).Update("name", vtapName)
				}
				// check and update launch_server_id
				if vtap.LaunchServerID != pod.ID {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) launch_server_id from %d to %d",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.LaunchServerID, pod.ID,
					)
					db.Model(&vtap).Update("launch_server_id", pod.ID)
				}
				// check and update region
				if vtap.Region != pod.Region {
					log.Infof(
						"ORG(id=%d database=%s) update vtap (%s) region from %s to %s",
						db.ORGID, db.Name, vtap.Lcuuid, vtap.Region, pod.Region,
					)
					db.Model(&vtap).Update("region", pod.Region)
				}
			}
		}
	}
	log.Debugf("ORG(id=%d database=%s) vtap launch_server check end", db.ORGID, db.Name)
}

func (v *VTapCheck) typeCheck(db *mysql.DB) {
	var vtaps []mysql.VTap
	var podNodes []mysql.PodNode
	var conns []mysql.VMPodNodeConnection

	log.Debugf("ORG(id=%d database=%s) vtap type check start", db.ORGID, db.Name)

	db.Find(&podNodes)
	idToPodNode := make(map[int]*mysql.PodNode)
	for i, podNode := range podNodes {
		idToPodNode[podNode.ID] = &podNodes[i]
	}

	db.Find(&conns)
	vmIDToPodNodeID := make(map[int]int)
	podNodeIDToVMID := make(map[int]int)
	for _, conn := range conns {
		vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		podNodeIDToVMID[conn.PodNodeID] = conn.VMID
	}

	var vms []mysql.VM
	if err := db.Where("htype in ?", []int{common.VM_HTYPE_BM_C, common.VM_HTYPE_BM_N, common.VM_HTYPE_BM_S}).Find(&vms).Error; err != nil {
		log.Error(err)
	}
	vmIDToVMType := make(map[int]int)
	for _, vm := range vms {
		vmIDToVMType[vm.ID] = vm.HType
	}

	db.Where(
		"type IN (?)",
		[]int{common.VTAP_TYPE_WORKLOAD_V, common.VTAP_TYPE_WORKLOAD_P, common.VTAP_TYPE_POD_HOST},
	).Find(&vtaps)
	for _, vtap := range vtaps {
		if vtap.Type == common.VTAP_TYPE_WORKLOAD_V || vtap.Type == common.VTAP_TYPE_WORKLOAD_P {
			var vm mysql.VM
			if ret := db.Where("lcuuid = ?", vtap.Lcuuid).First(&vm); ret.Error != nil {
				continue
			}
			podNodeID, ok := vmIDToPodNodeID[vm.ID]
			if !ok {
				continue
			}
			podNode, ok := idToPodNode[podNodeID]
			if !ok {
				log.Infof(
					"ORG(id=%d database=%s) pod_node (%s) not found, will not re-discovery vtap (%s), please check db data",
					db.ORGID, db.Name, podNodeID, vtap.Name,
				)
				continue
			}
			if vtap.LaunchServer != podNode.IP {
				log.Infof(
					"ORG(id=%d database=%s) vtap (%s) launch_server (%s) not equal to podNode (%s), will not re-discovery vtap",
					db.ORGID, db.Name, vtap.Name, vtap.LaunchServer, podNode.IP,
				)
				continue
			}
		} else {
			var podNode mysql.PodNode
			if ret := db.Where("lcuuid = ?", vtap.Lcuuid).First(&podNode); ret.Error != nil {
				continue
			}
			vmID, ok := podNodeIDToVMID[podNode.ID]
			if !ok {
				continue
			}
			if vmType, ok := vmIDToVMType[vmID]; ok && utils.IsVMofBMHtype(vmType) {
				continue
			}
		}

		log.Infof(
			"ORG(id=%d database=%s) delete vtap (%s) type (%d), because has vm_pod_node_connection",
			db.ORGID, db.Name, vtap.Name, vtap.Type,
		)
		db.Delete(&vtap)
	}

	log.Debugf("ORG(id=%d database=%s) vtap type check end", db.ORGID, db.Name)
}

func (v *VTapCheck) deleteLostVTap(db *mysql.DB) {
	var vtaps []*mysql.VTap
	db.Where("state = ? and type not in (?)",
		common.VTAP_STATE_NOT_CONNECTED,
		[]int{common.VTAP_TYPE_DEDICATED, common.VTAP_TYPE_TUNNEL_DECAPSULATION},
	).Find(&vtaps)

	if len(vtaps) == 0 {
		return
	}

	var ids []int
	for _, vtap := range vtaps {
		ids = append(ids, vtap.ID)
		log.Infof("ORG(id=%d database=%s) delete lost vtap(name: %s, ctrl_ip: %s, ctrl_mac: %s)",
			db.ORGID, db.Name, vtap.Name, vtap.CtrlIP, vtap.CtrlMac)
	}
	db.Delete(&vtaps, ids)
}
