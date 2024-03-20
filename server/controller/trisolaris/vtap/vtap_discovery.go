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
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"gorm.io/gorm"

	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type VTapRegister struct {
	tapMode               int
	vTapGroupID           string
	defaultVTapGroup      string
	vTapAutoRegister      bool
	agentUniqueIdentifier int
	teamID                int
	vTapInfo              *VTapInfo
	VTapLKData
	ORGID
}

type VTapLKData struct {
	ctrlIP  string
	ctrlMac string
	hostIPs []string
	host    string
	region  string
	ORGID
}

type VTapLKResult struct {
	VTapType       int
	LaunchServer   string
	LaunchServerID int
	VTapName       string
	AZ             string
	Region         string
	Lcuuid         string
}

func NewVTapLkData(ctrlIP string, ctrlMac string, ips []string, host string, region string, orgID ORGID) *VTapLKData {
	return &VTapLKData{
		ctrlIP:  ctrlIP,
		ctrlMac: ctrlMac,
		hostIPs: ips,
		host:    host,
		region:  region,
		ORGID:   orgID,
	}
}

func FilterSlice(s []string, filter func(x string) bool) []string {
	if len(s) == 0 {
		return nil
	}
	newS := s[:0]
	for _, x := range s {
		if !filter(x) {
			newS = append(newS, x)
		}
	}

	return newS
}

func newVTapRegister(tapMode int, ctrlIP string, ctrlMac string, hostIPs []string,
	host string, vTapGroupID string, agentUniqueIdentifier int, vTapInfo *VTapInfo, teamID int) *VTapRegister {
	hIPs := FilterSlice(hostIPs, func(x string) bool {
		if x == "127.0.0.1" {
			return true
		}
		return false
	})
	hIPs = append(hIPs, ctrlIP)
	return &VTapRegister{
		tapMode: tapMode,
		VTapLKData: VTapLKData{
			ctrlIP:  ctrlIP,
			ctrlMac: ctrlMac,
			hostIPs: hIPs,
			host:    host,
			ORGID:   vTapInfo.ORGID},
		vTapGroupID:           vTapGroupID,
		agentUniqueIdentifier: agentUniqueIdentifier,
		vTapInfo:              vTapInfo,
		teamID:                teamID,
		ORGID:                 vTapInfo.ORGID,
	}
}

func (r *VTapRegister) String() string {
	return fmt.Sprintf("%+v", *r)
}

func (r *VTapRegister) getVTapGroupLcuuid(db *gorm.DB) string {
	if r.vTapGroupID != "" {
		vtapGroup := &models.VTapGroup{}
		ret := db.Where("short_uuid = ?", r.vTapGroupID).First(vtapGroup)
		if ret.Error != nil {
			log.Error(r.Logf("vtap group(short_uuid=%s) not found", r.vTapGroupID))
			return r.defaultVTapGroup
		} else {
			return vtapGroup.Lcuuid
		}
	}

	return r.defaultVTapGroup
}

func (r *VTapRegister) finishLog(dbVTap *models.VTap) {
	log.Infof(r.Logf(
		"finish register vtap (type: %d tap_mode:%d, name:%s ctrl_ip: %s ctrl_mac: %s "+
			"launch_server: %s launch_server_id: %d vtap_group_lcuuid: %s az: %s team_id: %d lcuuid: %s)",
		dbVTap.Type, dbVTap.TapMode, dbVTap.Name, dbVTap.CtrlIP, dbVTap.CtrlMac, dbVTap.LaunchServer,
		dbVTap.LaunchServerID, dbVTap.VtapGroupLcuuid, dbVTap.AZ, dbVTap.TeamID, dbVTap.Lcuuid))
}

// 采集器名称不支持空格和:
var reg = regexp.MustCompile(` |:`)

func (r *VTapRegister) insertToDB(dbVTap *models.VTap, db *gorm.DB) bool {
	vTapName := reg.ReplaceAllString(dbVTap.Name, "-")
	oldVTap, err := dbmgr.DBMgr[models.VTap](db).GetFromName(vTapName)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		dbVTap.Name = vTapName
	} else {
		if err == nil {
			log.Errorf(r.Logf("agent(%s) name=%s already exist", r, vTapName))
			if oldVTap.State == VTAP_STATE_NOT_CONNECTED {
				log.Warningf(r.Logf("vtap(%s) info (ctrl_ip: %s, ctr_mac: %s) change to (ctrl_ip: %s, ctr_mac: %s)", vTapName,
					oldVTap.CtrlIP, oldVTap.CtrlMac, dbVTap.CtrlIP, dbVTap.CtrlMac))
				oldVTap.CtrlMac = dbVTap.CtrlMac
				oldVTap.CtrlIP = dbVTap.CtrlIP
				oldVTap.LaunchServer = dbVTap.LaunchServer
				err := dbmgr.DBMgr[models.VTap](db).Save(oldVTap)
				if err != nil {
					log.Error(r.Log(err.Error()))
					return false
				}
				*dbVTap = *oldVTap
				return true
			}
		} else {
			log.Errorf(r.Logf("query agent(%s) from DB table vtap failed, err: %s", vTapName, err))
		}
		return false
	}
	if r.vTapAutoRegister {
		dbVTap.State = VTAP_STATE_NORMAL
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(dbVTap).Error; err != nil {
			log.Errorf(r.Logf("insert agent(%s) to DB faild, err: %s", r, err))
			return err
		}
		r.finishLog(dbVTap)
		return nil
	})

	if err != nil {
		log.Error(r.Log(err.Error()))
		return false
	}
	return true
}

func (l *VTapLKData) getKey() string {
	return fmt.Sprintf("%s-%s", l.ctrlIP, l.ctrlMac)
}

func (l *VTapLKData) LookUpVTapByHost(db *gorm.DB) *VTapLKResult {
	hostMgr := dbmgr.DBMgr[models.Host](db)
	dbHost, err := hostMgr.GetFirstFromBatchIPs(l.hostIPs)
	if err != nil {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table host_device(ip in (%s)) without finding data, err: %s",
			l.getKey(), l.hostIPs, err))
		dbHost, err = hostMgr.GetFromName(l.host)
		if err != nil {
			log.Errorf(l.Logf("failed to register agent(%s) by querying DB table host_device(name in (%s)) without finding data, err: %s",
				l.getKey(), l.host, err))
			return nil
		}
	}
	var (
		vTapType       int
		launchServer   string
		launchServerID int
		vTapName       string
		az             string
		region         string
	)
	if dbHost.HType == HOST_HTYPE_HYPER_V {
		vTapType = VTAP_TYPE_HYPER_V
	} else {
		vTapType = VTAP_TYPE_KVM
	}
	launchServer = dbHost.IP
	launchServerID = dbHost.ID
	vTapName = fmt.Sprintf("%s-H%d", dbHost.Name, dbHost.ID)
	az = dbHost.AZ
	region = dbHost.Region

	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   launchServer,
		LaunchServerID: launchServerID,
		VTapName:       vTapName,
		AZ:             az,
		Region:         region,
		Lcuuid:         uuid.NewString(),
	}
}

func (r *VTapRegister) registerVTapByHost(db *gorm.DB) (*models.VTap, bool) {
	vtapLKData := r.LookUpVTapByHost(db)
	if vtapLKData == nil {
		return nil, false
	}
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vtapLKData.VTapType,
		LaunchServer:    vtapLKData.LaunchServer,
		LaunchServerID:  vtapLKData.LaunchServerID,
		Name:            vtapLKData.VTapName,
		AZ:              vtapLKData.AZ,
		Region:          vtapLKData.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vtapLKData.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) LookUpVTapByPodNode(db *gorm.DB) *VTapLKResult {
	podNodeMgr := dbmgr.DBMgr[models.PodNode](db)
	podNodes, err := podNodeMgr.GetBatchFromIPs(l.hostIPs)
	if err != nil || len(podNodes) == 0 {
		podNodes, err = podNodeMgr.GetBatchFromName(l.host)
		if err != nil || len(podNodes) == 0 {
			log.Errorf(l.Logf("failed to register agent(%s) by querying DB table pod_node(ip in (%s) or name in (%s)) without finding data",
				l.getKey(), l.hostIPs, l.host))
			return nil
		}
	}
	podNodeIDs := make([]int, 0, len(podNodes))
	idToPodNode := make(map[int]*models.PodNode)
	for _, podNode := range podNodes {
		podNodeIDs = append(podNodeIDs, podNode.ID)
		idToPodNode[podNode.ID] = podNode
	}
	vmPodNodeConnMgr := dbmgr.DBMgr[models.VMPodNodeConnection](db)
	vmPodNodeConns, err := vmPodNodeConnMgr.GetBatchFromPodNodeIDs(podNodeIDs)

	vmIDToConn := make(map[int]*models.VMPodNodeConnection)
	podNodeIdToConn := make(map[int]*models.VMPodNodeConnection)
	vmIDs := make([]int, 0, len(vmPodNodeConns))
	for _, conn := range vmPodNodeConns {
		vmIDToConn[conn.VMID] = conn
		podNodeIdToConn[conn.PodNodeID] = conn
		vmIDs = append(vmIDs, conn.VMID)
	}

	vifMgr := dbmgr.DBMgr[models.VInterface](db)
	var matchVif *models.VInterface
	matchVif, err = vifMgr.GetVInterfaceFromDeviceIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_POD_NODE,
		podNodeIDs)
	if err != nil {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface(mac=%s, region=%s, devicetype=%d, deviceid in (%v)) without finding data, err: %s",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_POD_NODE, podNodeIDs, err))
		if len(vmIDs) > 0 {
			matchVif, err = vifMgr.GetVInterfaceFromDeviceIDs(
				l.ctrlMac,
				l.region,
				VIF_DEVICE_TYPE_VM,
				vmIDs)
			if err != nil {
				log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface(mac=%s, region=%s, devicetype=%d, deviceid in (%v)) without finding data, err: %s",
					l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_VM, vmIDs, err))
				return nil
			}
		} else {
			return nil
		}
	}
	var (
		matchPodNode *models.PodNode
		vTapType     int
	)
	if matchVif.DeviceType == VIF_DEVICE_TYPE_POD_NODE {
		matchPodNode = idToPodNode[matchVif.DeviceID]
		if conn, ok := podNodeIdToConn[matchVif.DeviceID]; ok {
			vm, err := dbmgr.DBMgr[models.VM](db).GetFromID(conn.VMID)
			if err != nil {
				log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vm(id=%d) without finding data, err: %s",
					l.getKey(), conn.VMID, err))
				return nil
			}
			if IsVMofBMHtype(vm.HType) == true {
				vTapType = VTAP_TYPE_POD_HOST
			} else {
				vTapType = VTAP_TYPE_POD_VM
			}
		} else {
			vTapType = VTAP_TYPE_POD_HOST
		}
	} else {
		if conn, ok := vmIDToConn[matchVif.DeviceID]; ok {
			matchPodNode = idToPodNode[conn.PodNodeID]
			vm, err := dbmgr.DBMgr[models.VM](db).GetFromID(matchVif.DeviceID)
			if err != nil {
				log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vm(id=%d) without finding data, err: %s", l.getKey(), matchVif.DeviceID, err))
				return nil
			}
			if IsVMofBMHtype(vm.HType) == true {
				vTapType = VTAP_TYPE_POD_HOST
			} else {
				vTapType = VTAP_TYPE_POD_VM
			}
		}
	}
	if matchPodNode == nil {
		log.Errorf(l.Logf("failed to register agent(%s) pod_node not found", l.getKey()))
		return nil
	}
	vTapName := fmt.Sprintf("%s-P%d", matchPodNode.Name, matchPodNode.ID)
	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   matchPodNode.IP,
		LaunchServerID: matchPodNode.ID,
		VTapName:       vTapName,
		AZ:             matchPodNode.AZ,
		Region:         matchPodNode.Region,
		Lcuuid:         matchPodNode.Lcuuid,
	}
}

func (r *VTapRegister) registerVTapByPodNode(db *gorm.DB) (*models.VTap, bool) {
	vtapLKResult := r.LookUpVTapByPodNode(db)
	if vtapLKResult == nil {
		return nil, false
	}
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vtapLKResult.VTapType,
		LaunchServer:    vtapLKResult.LaunchServer,
		LaunchServerID:  vtapLKResult.LaunchServerID,
		Name:            vtapLKResult.VTapName,
		AZ:              vtapLKResult.AZ,
		Region:          vtapLKResult.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) LookUpVTapByPod(db *gorm.DB) *VTapLKResult {
	lanVifIDs, lanVifIDToIP := l.getLanIPVIFIDs(db)
	wanVifIDs, wanVifIDToIP := l.getWanIPVIFIDs(db)
	vifIDs := make([]int, 0, len(lanVifIDs)+len(wanVifIDs))
	if len(lanVifIDs) > 0 {
		vifIDs = append(vifIDs, lanVifIDs...)
	}
	if len(wanVifIDs) > 0 {
		vifIDs = append(vifIDs, wanVifIDs...)
	}
	if len(vifIDs) == 0 {
		return nil
	}

	vifs, err := dbmgr.DBMgr[models.VInterface](db).GetBatchVInterfaceFromIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_POD,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface(mac=%s, region=%s, devicetype=%d, vifid in (%v)) without finding data",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_POD, vifIDs))
		if err != nil {
			log.Error(err)
		}
		return nil
	}
	deviceIDs := make([]int, 0, len(vifs))
	deviceIDToVifID := make(map[int]int)
	for _, vif := range vifs {
		deviceIDs = append(deviceIDs, vif.DeviceID)
		deviceIDToVifID[vif.DeviceID] = vif.ID
	}
	pod, err := dbmgr.DBMgr[models.Pod](db).GetFirstFromBatchIDs(deviceIDs)
	if err != nil {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table pod(id in %v) without finding data, err: %s", l.getKey(), deviceIDs, err))
		return nil
	}

	var launchServer string
	if vifID, ok := deviceIDToVifID[pod.ID]; ok {
		launchServer = lanVifIDToIP[vifID]
		if launchServer == "" {
			launchServer = wanVifIDToIP[vifID]
		}
	}
	vTapName := fmt.Sprintf("%s-K%d", pod.Name, pod.ID)
	return &VTapLKResult{
		VTapType:       VTAP_TYPE_K8S_SIDECAR,
		LaunchServer:   launchServer,
		LaunchServerID: pod.ID,
		VTapName:       vTapName,
		AZ:             pod.AZ,
		Region:         pod.Region,
		Lcuuid:         pod.Lcuuid,
	}
}

func (r *VTapRegister) registerVTapByPod(db *gorm.DB) (*models.VTap, bool) {
	vtapLKResult := r.LookUpVTapByPod(db)
	if vtapLKResult == nil {
		return nil, false
	}
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vtapLKResult.VTapType,
		LaunchServer:    vtapLKResult.LaunchServer,
		LaunchServerID:  vtapLKResult.LaunchServerID,
		Name:            vtapLKResult.VTapName,
		AZ:              vtapLKResult.AZ,
		Region:          vtapLKResult.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) getLanIPVIFIDs(db *gorm.DB) ([]int, map[int]string) {
	lanIPMgr := dbmgr.DBMgr[models.LANIP](db)
	lanIPs, err := lanIPMgr.GetBatchFromIPs(l.hostIPs)
	if err != nil || len(lanIPs) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface_ip(ip in (%s)) without finding data", l.getKey(), l.hostIPs))
		if err != nil {
			log.Error(l.Logf("%s", err))
		}
		return nil, nil
	}
	vifIDToIP := make(map[int]string)
	lanIDs := make([]int, 0, len(lanIPs))
	for _, lanIP := range lanIPs {
		lanIDs = append(lanIDs, lanIP.VInterfaceID)
		vifIDToIP[lanIP.VInterfaceID] = lanIP.IP
	}
	return lanIDs, vifIDToIP
}

func (l *VTapLKData) getWanIPVIFIDs(db *gorm.DB) ([]int, map[int]string) {
	wanIPs, err := dbmgr.DBMgr[models.WANIP](db).GetBatchFromIPs(l.hostIPs)
	if err != nil || len(wanIPs) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table ip_resource(ip in (%s)) without finding data", l.getKey(), l.hostIPs))
		if err != nil {
			log.Error(l.Logf("%s", err))
		}
		return nil, nil
	}
	vifIDToIP := make(map[int]string)
	wanIDs := make([]int, 0, len(wanIPs))
	for _, wanIP := range wanIPs {
		wanIDs = append(wanIDs, wanIP.VInterfaceID)
		vifIDToIP[wanIP.VInterfaceID] = wanIP.IP
	}
	return wanIDs, vifIDToIP
}

func (l *VTapLKData) LookUpMirrorVTapByIP(db *gorm.DB) *VTapLKResult {
	lanVifIDs, lanVifIDToIP := l.getLanIPVIFIDs(db)
	wanVifIDs, wanVifIDToIP := l.getWanIPVIFIDs(db)
	vifIDs := make([]int, 0, len(lanVifIDs)+len(wanVifIDs))
	if len(lanVifIDs) > 0 {
		vifIDs = append(vifIDs, lanVifIDs...)
	}
	if len(wanVifIDs) > 0 {
		vifIDs = append(vifIDs, wanVifIDs...)
	}
	if len(vifIDs) == 0 {
		return nil
	}

	vifMgr := dbmgr.DBMgr[models.VInterface](db)
	vifs, err := vifMgr.GetBatchVInterfaceFromIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface(mac=%s, region=%s, devicetype=%d, vifid in (%v)) without finding data",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_VM, vifIDs))
		if err != nil {
			log.Error(l.Logf("%s", err))
		}
		return nil
	}
	deviceIDs := make([]int, 0, len(vifs))
	deviceIDToVifID := make(map[int]int)
	for _, vif := range vifs {
		deviceIDs = append(deviceIDs, vif.DeviceID)
		deviceIDToVifID[vif.DeviceID] = vif.ID
	}
	vms, err := dbmgr.DBMgr[models.VM](db).GetBatchFromIDs(deviceIDs)
	if err != nil || len(vms) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vm(id in (%v)) without finding data", l.getKey(), deviceIDs))
		if err != nil {
			log.Error(l.Logf("%s", err))
		}
		return nil
	}

	vmLaunchServers := make([]string, 0, len(vms))
	launchServerToVM := make(map[string]*models.VM)
	for _, vm := range vms {
		if vm.LaunchServer == "" {
			log.Errorf(l.Logf("failed to register agent(%s), vm(id=%d) not launch server", l.getKey(), vm.ID))
			continue
		}
		if !Find[string](vmLaunchServers, vm.LaunchServer) {
			vmLaunchServers = append(vmLaunchServers, vm.LaunchServer)
			launchServerToVM[vm.LaunchServer] = vm
		}
	}
	if len(vmLaunchServers) == 0 {
		return nil
	}
	host, err := dbmgr.DBMgr[models.Host](db).GetFirstFromBatchIPs(vmLaunchServers)
	if err != nil {
		log.Error(l.Logf("failed to register agent(%s) by querying DB table host(ip in(%s)) without finding data", l.getKey(), vmLaunchServers))
		return nil
	}

	var vTapName, launchServer, az, region, lcuuid string
	var vTapType, launchServerID int
	if host.HType == HOST_HTYPE_ESXI {
		vTapName = fmt.Sprintf("%s-H%d", host.Name, host.ID)
		vTapType = VTAP_TYPE_ESXI
		launchServer = host.IP
		launchServerID = host.ID
		az = host.AZ
		region = host.Region
		lcuuid = uuid.NewString()
	} else {
		vm, ok := launchServerToVM[host.IP]
		if ok == false {
			log.Errorf(l.Logf("failed to register agent(%s), host_device(ip=%s) not found vm", l.getKey(), host.IP))
			return nil
		}
		if IsVMofBMHtype(vm.HType) == true {
			vTapType = VTAP_TYPE_WORKLOAD_P
		} else {
			vTapType = VTAP_TYPE_WORKLOAD_V
		}
		if vifID, ok := deviceIDToVifID[vm.ID]; ok {
			launchServer = lanVifIDToIP[vifID]
			if launchServer == "" {
				launchServer = wanVifIDToIP[vifID]
			}
		}

		vTapName = fmt.Sprintf("%s-W%d", vm.Name, vm.ID)
		launchServerID = vm.ID
		az = vm.AZ
		region = vm.Region
		lcuuid = vm.Lcuuid
	}
	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   launchServer,
		LaunchServerID: launchServerID,
		VTapName:       vTapName,
		AZ:             az,
		Region:         region,
		Lcuuid:         lcuuid,
	}
}

func (r *VTapRegister) registerMirrorVTapByIP(db *gorm.DB) (*models.VTap, bool) {
	vtapLKResult := r.LookUpMirrorVTapByIP(db)
	if vtapLKResult == nil {
		return nil, false
	}
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vtapLKResult.VTapType,
		LaunchServer:    vtapLKResult.LaunchServer,
		LaunchServerID:  vtapLKResult.LaunchServerID,
		Name:            vtapLKResult.VTapName,
		AZ:              vtapLKResult.AZ,
		Region:          vtapLKResult.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) LookUpLocalVTapByIP(db *gorm.DB) *VTapLKResult {
	lanVifIDs, lanVifIDToIP := l.getLanIPVIFIDs(db)
	wanVifIDs, wanVifIDToIP := l.getWanIPVIFIDs(db)
	vifIDs := make([]int, 0, len(lanVifIDs)+len(wanVifIDs))
	if len(lanVifIDs) > 0 {
		vifIDs = append(vifIDs, lanVifIDs...)
	}
	if len(wanVifIDs) > 0 {
		vifIDs = append(vifIDs, wanVifIDs...)
	}
	if len(vifIDs) == 0 {
		return nil
	}
	vifs, err := dbmgr.DBMgr[models.VInterface](db).GetBatchVInterfaceFromIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vinterface(mac=%s, region=%s, devicetype=%d, vifid in (%v)) without finding data",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_VM, vifIDs))
		if err != nil {
			log.Error(l.Logf("%s", err))
		}
		return nil
	}
	deviceIDs := make([]int, 0, len(vifs))
	deviceIDToVifID := make(map[int]int)
	for _, vif := range vifs {
		deviceIDs = append(deviceIDs, vif.DeviceID)
		deviceIDToVifID[vif.DeviceID] = vif.ID
	}
	vm, err := dbmgr.DBMgr[models.VM](db).GetFirstFromBatchIDs(deviceIDs)
	if err != nil {
		log.Errorf(l.Logf("failed to register agent(%s) by querying DB table vm(id in %v) without finding data, err: %s", l.getKey(), deviceIDs, err))
		return nil
	}
	var (
		vTapType     int
		launchServer string
	)
	if IsVMofBMHtype(vm.HType) == true {
		vTapType = VTAP_TYPE_WORKLOAD_P
	} else {
		vTapType = VTAP_TYPE_WORKLOAD_V
	}
	if vifID, ok := deviceIDToVifID[vm.ID]; ok {
		launchServer = lanVifIDToIP[vifID]
		if launchServer == "" {
			launchServer = wanVifIDToIP[vifID]
		}
	}
	vTapName := fmt.Sprintf("%s-W%d", vm.Name, vm.ID)
	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   launchServer,
		LaunchServerID: vm.ID,
		VTapName:       vTapName,
		AZ:             vm.AZ,
		Region:         vm.Region,
		Lcuuid:         vm.Lcuuid,
	}
}

func (r *VTapRegister) registerLocalVTapByIP(db *gorm.DB) (*models.VTap, bool) {
	vtapLKResult := r.LookUpLocalVTapByIP(db)
	if vtapLKResult == nil {
		return nil, false
	}
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vtapLKResult.VTapType,
		LaunchServer:    vtapLKResult.LaunchServer,
		LaunchServerID:  vtapLKResult.LaunchServerID,
		Name:            vtapLKResult.VTapName,
		AZ:              vtapLKResult.AZ,
		Region:          vtapLKResult.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerVTapAnalyzerTapMode(db *gorm.DB) (*models.VTap, bool) {
	az, err := dbmgr.DBMgr[models.AZ](db).GetFromRegion(r.region)
	if err != nil {
		log.Errorf(r.Logf("failed to register agent(%s), because no az in region %s", r.getKey(), r.region))
		return nil, false
	}

	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            VTAP_TYPE_DEDICATED,
		Name:            r.host,
		LaunchServer:    r.ctrlIP,
		AZ:              az.Lcuuid,
		Region:          r.region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          uuid.NewString(),
	}
	result := r.insertToDB(dbVTap, db)
	if result == false {
		return nil, false
	}
	return dbVTap, true
}

func (r *VTapRegister) registerVTapByCtrlIP(db *gorm.DB) (*models.VTap, bool) {
	vInterfaceID := 0
	lanIPMgr := dbmgr.DBMgr[models.LANIP](db)
	lanIP, err := lanIPMgr.GetByOption(lanIPMgr.WithIP(r.ctrlIP))
	if err != nil || lanIP == nil {
		log.Errorf(r.Logf("failed to register agent(%s) by querying DB table vinterface_ip(ip = %s) without finding data", r.getKey(), r.ctrlIP))
		if err != nil {
			log.Error(err)
		}
		wanIPMgr := dbmgr.DBMgr[models.WANIP](db)
		wanIP, err := wanIPMgr.GetByOption(wanIPMgr.WithIP(r.ctrlIP))
		if err != nil || wanIP == nil {
			log.Errorf("failed to register agent(%s) by querying DB table ip_resource(ip = %s) without finding data", r.getKey(), r.ctrlIP)
			if err != nil {
				log.Error(err)
			}
			return nil, false
		}
		vInterfaceID = wanIP.VInterfaceID
	} else {
		vInterfaceID = lanIP.VInterfaceID
	}
	vif, err := dbmgr.DBMgr[models.VInterface](db).GetFromID(vInterfaceID)
	if err != nil || vif == nil {
		log.Errorf("failed to register agent(%s) by querying DB table vinterface(id = %d) without finding data",
			r.getKey(), vInterfaceID)
		if err != nil {
			log.Error(err)
		}
		return nil, false
	}

	vm, err := dbmgr.DBMgr[models.VM](db).GetFromID(vif.DeviceID)
	if err != nil || vm == nil {
		log.Errorf("failed to register agent(%s) by querying DB table vm(id = %d) without finding data", r.getKey(), vif.DeviceID)
		if err != nil {
			log.Error(err)
		}
		return nil, false
	}
	var vTapType int
	if IsVMofBMHtype(vm.HType) == true {
		vTapType = VTAP_TYPE_WORKLOAD_P
	} else {
		vTapType = VTAP_TYPE_WORKLOAD_V
	}
	vTapName := fmt.Sprintf("%s-W%d", vm.Name, vm.ID)
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vTapType,
		LaunchServer:    r.ctrlIP,
		LaunchServerID:  vm.ID,
		Name:            vTapName,
		AZ:              vm.AZ,
		Region:          vm.Region,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         r.tapMode,
		TeamID:          r.teamID,
		Lcuuid:          vm.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerVTapByCtrlIPMac(db *gorm.DB) (vtap *models.VTap, ok bool) {
	switch r.tapMode {
	case TAPMODE_LOCAL:
		vtap, ok = r.registerVTapByHost(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerVTapByPodNode(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerVTapByPod(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerLocalVTapByIP(db)
	case TAPMODE_MIRROR:
		vtap, ok = r.registerVTapByHost(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerVTapByPodNode(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerVTapByPod(db)
		if ok == true {
			break
		}
		vtap, ok = r.registerMirrorVTapByIP(db)
	case TAPMODE_ANALYZER:
		vtap, ok = r.registerVTapAnalyzerTapMode(db)

	default:
		log.Errorf(r.vTapInfo.Logf("unkown tap_mode(%d) from agent(%s)", r.tapMode, r.getKey()))
	}

	return
}

func (r *VTapRegister) registerVTap(done func()) {
	defer done()
	v := r.vTapInfo
	vtapMgr := dbmgr.DBMgr[models.VTap](v.db)
	_, err := vtapMgr.GetByOption(
		vtapMgr.WithCtrlIP(r.ctrlIP),
		vtapMgr.WithCtrlMac(r.ctrlMac))
	if err == nil {
		log.Warningf(r.Logf(
			"agent(ctrl_ip: %s ctrl_mac: %s) already exist on DB",
			r.ctrlIP, r.ctrlMac))
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error(r.Log(err.Error()))
		return
	}
	vtapConfig := r.vTapInfo.GetVTapConfigFromShortID(r.vTapGroupID)
	if vtapConfig != nil {
		r.tapMode = vtapConfig.TapMode
	} else {
		r.tapMode = DefaultTapMode
	}
	r.region = v.getRegion()
	r.defaultVTapGroup = v.getDefaultVTapGroup()
	r.vTapAutoRegister = v.getVTapAutoRegister()
	log.Infof(r.Logf("register vtap: %s", r))
	var vtap *models.VTap
	ok := false
	switch r.agentUniqueIdentifier {
	case AGENT_IDENTIFIE_IP_AND_MAC:
		vtap, ok = r.registerVTapByCtrlIPMac(v.db)
	case AGENT_IDENTIFIE_IP:
		vtap, ok = r.registerVTapByCtrlIP(v.db)
	default:
		log.Errorf(r.Logf("unkown agent_unique_identifier(%d) from agent(%s)", r.agentUniqueIdentifier, r.getKey()))

	}

	if vtap != nil && ok == true {
		v.AddVTapCache(vtap)
		v.putChRegisterFisnish()
		log.Infof(r.Logf("finish register vtap: %s", r))
	}
}

func (r *VTapRegister) getKey() string {
	return fmt.Sprintf("%s-%s", r.ctrlIP, r.ctrlMac)
}
