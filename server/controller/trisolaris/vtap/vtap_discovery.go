/*
 * Copyright (c) 2022 Yunshan Networks
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

	. "github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/dbmgr"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/utils"
)

type VTapRegister struct {
	tapMode          int
	vTapGroupID      string
	defaultVTapGroup string
	vTapAutoRegister bool
	VTapLKData
}

type VTapLKData struct {
	ctrlIP  string
	ctrlMac string
	hostIPs []string
	host    string
	region  string
}

type VTapLKResult struct {
	VTapType       int
	LaunchServer   string
	LaunchServerID int
	VTapName       string
	AZ             string
	Lcuuid         string
}

func NewVTapLkData(ctrlIP string, ctrlMac string, ips []string, host string, region string) *VTapLKData {
	return &VTapLKData{
		ctrlIP:  ctrlIP,
		ctrlMac: ctrlMac,
		hostIPs: ips,
		host:    host,
		region:  region,
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
	host string, vTapGroupID string) *VTapRegister {
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
			host:    host},
		vTapGroupID: vTapGroupID,
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
			log.Error("vtap group(short_uuid=%s) not found", r.vTapGroupID)
			return r.defaultVTapGroup
		} else {
			return vtapGroup.Lcuuid
		}
	}

	return r.defaultVTapGroup
}

func finishLog(dbVTap *models.VTap) {
	log.Infof(
		"finish register vtap (type: %d name:%s ctrl_ip: %s ctrl_mac: %s "+
			"launch_server: %s launch_server_id: %d vtap_group_lcuuid: %s az: %s lcuuid: %s)",
		dbVTap.Type, dbVTap.Name, dbVTap.CtrlIP, dbVTap.CtrlMac, dbVTap.LaunchServer,
		dbVTap.LaunchServerID, dbVTap.VtapGroupLcuuid, dbVTap.AZ, dbVTap.Lcuuid)
}

// 采集器名称不支持空格和:
var reg = regexp.MustCompile(` |:`)

func (r *VTapRegister) insertToDB(dbVTap *models.VTap, db *gorm.DB) bool {
	vTapName := reg.ReplaceAllString(dbVTap.Name, "-")
	_, err := dbmgr.DBMgr[models.VTap](db).GetFromName(vTapName)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		dbVTap.Name = vTapName
	} else {
		if err == nil {
			log.Errorf("vtap (%s) already exist", vTapName)
		} else {
			log.Errorf("query vtap(%s) failed, %s", vTapName, err)
		}
		return false
	}
	if r.vTapAutoRegister {
		dbVTap.State = VTAP_STATE_NORMAL
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(dbVTap).Error; err != nil {
			log.Errorf("insert vtap(%s) faild, err: %s", r, err)
			return err
		}
		finishLog(dbVTap)
		return nil
	})

	if err != nil {
		log.Error(err)
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
		log.Errorf("vtap(%s) query host_device failed from host_ips(%s), err: %s", l.getKey(), l.hostIPs, err)
		dbHost, err = hostMgr.GetFromName(l.host)
		if err != nil {
			log.Errorf("vtap(%s) query host_device failed from host(%s), err: %s", l.getKey(), l.host, err)
			return nil
		}
	}
	var (
		vTapType       int
		launchServer   string
		launchServerID int
		vTapName       string
		az             string
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

	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   launchServer,
		LaunchServerID: launchServerID,
		VTapName:       vTapName,
		AZ:             az,
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
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         TAPMODE_LOCAL,
		Lcuuid:          vtapLKData.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func isVMofBMHtype(htype int) bool {
	if Find[int]([]int{VM_HTYPE_BM_C, VM_HTYPE_BM_N, VM_HTYPE_BM_S}, htype) == true {
		return true
	}
	return false
}

func (l *VTapLKData) LookUpVTapByPodNode(db *gorm.DB) *VTapLKResult {
	podNodeMgr := dbmgr.DBMgr[models.PodNode](db)
	podNodes, err := podNodeMgr.GetBatchFromIPs(l.hostIPs)
	if err != nil || len(podNodes) == 0 {
		podNodes, err = podNodeMgr.GetBatchFromName(l.host)
		if err != nil || len(podNodes) == 0 {
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
		if len(vmIDs) > 0 {
			matchVif, err = vifMgr.GetVInterfaceFromDeviceIDs(
				l.ctrlMac,
				l.region,
				VIF_DEVICE_TYPE_VM,
				vmIDs)
			if err != nil {
				log.Errorf("vtap(%s) vinterface(%s) not found, err(%s)", l.getKey(), l.ctrlMac, err)
				return nil
			}
		} else {
			log.Errorf("vtap(%s) vinterface(%s) not found, err(%s)", l.getKey(), l.ctrlMac, err)
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
				log.Errorf("vtap(%s), vm(id=%d) not in DB, err: %s", l.getKey(), conn.VMID, err)
				return nil
			}
			if isVMofBMHtype(vm.HType) == true {
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
				log.Errorf("vtap(%s), vm(id=%d) not in DB, err: %s", l.getKey(), matchVif.DeviceID, err)
				return nil
			}
			if isVMofBMHtype(vm.HType) == true {
				vTapType = VTAP_TYPE_POD_HOST
			} else {
				vTapType = VTAP_TYPE_POD_VM
			}
		}
	}
	if matchPodNode == nil {
		log.Errorf("vtap(%s) pod_node not found", l.getKey())
		return nil
	}
	vTapName := fmt.Sprintf("%s-P%d", matchPodNode.Name, matchPodNode.ID)
	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   matchPodNode.IP,
		LaunchServerID: matchPodNode.ID,
		VTapName:       vTapName,
		AZ:             matchPodNode.AZ,
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
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         TAPMODE_LOCAL,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) getLanIPVIFIDs(db *gorm.DB) ([]int, map[int]string) {
	lanIPMgr := dbmgr.DBMgr[models.LANIP](db)
	lanIPs, err := lanIPMgr.GetBatchFromIPs(l.hostIPs)
	if err != nil || len(lanIPs) == 0 {
		log.Errorf("vtap(%s) vinterface_ip(%s) not found", l.getKey(), l.hostIPs)
		if err != nil {
			log.Error(err)
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
		log.Errorf("vtap(%s) ip_resource(%s) not found", l.getKey(), l.hostIPs)
		if err != nil {
			log.Error(err)
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
	vifIDs, _ := l.getWanIPVIFIDs(db)
	if vifIDs == nil {
		return nil
	}

	vifMgr := dbmgr.DBMgr[models.VInterface](db)
	vifs, err := vifMgr.GetBatchVInterfaceFromIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf("vtap(%s) vinterface(mac: %s, region: %s, devicetype: %d) not found",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_VM)
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
	vms, err := dbmgr.DBMgr[models.VM](db).GetBatchFromIDs(deviceIDs)
	if err != nil || len(vms) == 0 {
		log.Errorf("vtap(%s), vms(id=%v) not in DB", l.getKey(), deviceIDs)
		if err != nil {
			log.Error(err)
		}
		return nil
	}

	vmLaunchServers := make([]string, 0, len(vms))
	for _, vm := range vms {
		if vm.LaunchServer == "" {
			log.Errorf("vtap(%s), vm(id=%d) not launch server", l.getKey(), vm.ID)
			continue
		}
		if !Find[string](vmLaunchServers, vm.LaunchServer) {
			vmLaunchServers = append(vmLaunchServers, vm.LaunchServer)
		}
	}
	if len(vmLaunchServers) == 0 {
		return nil
	}
	host, err := dbmgr.DBMgr[models.Host](db).GetFirstFromBatchIPs(vmLaunchServers)
	if err != nil {
		log.Error("vtap(%s) host(%s) not found", l.getKey(), vmLaunchServers)
		return nil
	}
	vTapName := fmt.Sprintf("%s-H%d", host.Name, host.ID)
	return &VTapLKResult{
		VTapType:       VTAP_TYPE_EXSI,
		LaunchServer:   host.IP,
		LaunchServerID: host.ID,
		VTapName:       vTapName,
		AZ:             host.AZ,
		Lcuuid:         uuid.NewString(),
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
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         TAPMODE_MIRROR,
		Lcuuid:          vtapLKResult.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (l *VTapLKData) LookUpLocalVTapByIP(db *gorm.DB) *VTapLKResult {
	vifIDs, vifIDToIP := l.getLanIPVIFIDs(db)
	if vifIDs == nil {
		vifIDs, vifIDToIP = l.getWanIPVIFIDs(db)
		if vifIDs == nil {
			return nil
		}
	}
	vifs, err := dbmgr.DBMgr[models.VInterface](db).GetBatchVInterfaceFromIDs(
		l.ctrlMac,
		l.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf("vtap(%s) vinterface(mac: %s, region: %s, devicetype: %d) not found",
			l.getKey(), l.ctrlMac, l.region, VIF_DEVICE_TYPE_VM)
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
	vm, err := dbmgr.DBMgr[models.VM](db).GetFirstFromBatchIDs(deviceIDs)
	if err != nil {
		log.Errorf("vtap(%s), vm(id=%v) not in DB, err: %s", l.getKey(), deviceIDs, err)
		return nil
	}
	var (
		vTapType     int
		launchServer string
	)
	if isVMofBMHtype(vm.HType) == true {
		vTapType = VTAP_TYPE_WORKLOAD_P
	} else {
		vTapType = VTAP_TYPE_WORKLOAD_V
	}
	if vifID, ok := deviceIDToVifID[vm.ID]; ok {
		launchServer = vifIDToIP[vifID]
	}
	vTapName := fmt.Sprintf("%s-W%d", vm.Name, vm.ID)
	return &VTapLKResult{
		VTapType:       vTapType,
		LaunchServer:   launchServer,
		LaunchServerID: vm.ID,
		VTapName:       vTapName,
		AZ:             vm.AZ,
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
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         TAPMODE_LOCAL,
		Lcuuid:          vtapLKResult.AZ,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerVTapAnalyzerTapMode(db *gorm.DB) *models.VTap {
	az, err := dbmgr.DBMgr[models.AZ](db).GetFromRegion(r.region)
	if err != nil {
		log.Errorf("vtap(%s) no az in region %s", r.getKey(), r.region)
		return nil
	}

	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            VTAP_TYPE_DEDICATED,
		Name:            r.host,
		LaunchServer:    r.ctrlIP,
		AZ:              az.Lcuuid,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(db),
		State:           VTAP_STATE_PENDING,
		TapMode:         TAPMODE_ANALYZER,
		Lcuuid:          uuid.NewString(),
	}
	result := r.insertToDB(dbVTap, db)
	if result == false {
		return nil
	}
	return dbVTap
}

func (r *VTapRegister) registerVTap(v *VTapInfo, done func()) {
	defer done()
	vtapMgr := dbmgr.DBMgr[models.VTap](v.db)
	_, err := vtapMgr.GetByOption(
		vtapMgr.WithCtrlIP(r.ctrlIP),
		vtapMgr.WithCtrlMac(r.ctrlMac))
	if err == nil {
		log.Warningf(
			"vtap(ctrl_ip: %s ctrl_mac: %s) already exist on DB",
			r.ctrlIP, r.ctrlMac)
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error(err)
		return
	}
	r.region = v.getRegion()
	r.defaultVTapGroup = v.getDefaultVTapGroup()
	r.vTapAutoRegister = v.getVTapAutoRegister()
	log.Infof("register vtap: %s", r)
	var vtap *models.VTap
	ok := false
	for {
		vtap, ok = r.registerVTapByHost(v.db)
		if ok == true {
			break
		}
		vtap, ok = r.registerVTapByPodNode(v.db)
		if ok == true {
			break
		}
		vtap, ok = r.registerLocalVTapByIP(v.db)
		if ok == true {
			break
		}
		vtap, ok = r.registerMirrorVTapByIP(v.db)
		if ok == true {
			break
		}
		break
	}

	if vtap != nil {
		v.AddVTapCache(vtap)
		v.putChRegisterFisnish()
	}
}

func (r *VTapRegister) getKey() string {
	return fmt.Sprintf("%s-%s", r.ctrlIP, r.ctrlMac)
}
