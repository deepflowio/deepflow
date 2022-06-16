package vtap

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"
	"gorm.io/gorm"

	. "server/controller/common"
	models "server/controller/db/mysql"
	"server/controller/trisolaris/dbmgr"
	. "server/controller/trisolaris/utils"
)

type VTapRegister struct {
	tapMode          int
	ctrlIP           string
	ctrlMac          string
	hostIPs          []string
	host             string
	vTapGroupID      string
	region           string
	defaultVTapGroup string
	vTapAutoRegister bool
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
		tapMode:     tapMode,
		ctrlIP:      ctrlIP,
		ctrlMac:     ctrlMac,
		hostIPs:     hIPs,
		host:        host,
		vTapGroupID: vTapGroupID,
	}
}

func (r *VTapRegister) String() string {
	return fmt.Sprintf("%+v", *r)
}

func (r *VTapRegister) getVTapGroupLcuuid() string {
	if r.vTapGroupID != "" {
		return r.vTapGroupID
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
		vTapConfigFile := &models.VTapConfigFile{
			VTapLcuuid: dbVTap.Lcuuid,
		}
		if err := tx.Create(dbVTap).Error; err != nil {
			log.Errorf("insert vtap(%s) faild, err: %s", r, err)
			return err
		}

		if err := tx.Create(vTapConfigFile).Error; err != nil {
			log.Errorf("insert vtap(%s) config file faild, err: %s", r, err)
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

func (r *VTapRegister) registerVTapByHost(db *gorm.DB) (*models.VTap, bool) {
	hostMgr := dbmgr.DBMgr[models.Host](db)
	dbHost, err := hostMgr.GetFirstFromBatchIPs(r.hostIPs)
	if err != nil {
		log.Errorf("vtap(%s) query host_device failed from host_ips(%s), err: %s", r.ctrlIP, r.hostIPs, err)
		dbHost, err = hostMgr.GetFromName(r.host)
		if err != nil {
			log.Errorf("vtap(%s) query host_device failed from host(%s), err: %s", r.ctrlIP, r.host, err)
			return nil, false
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
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vTapType,
		LaunchServer:    launchServer,
		LaunchServerID:  launchServerID,
		Name:            vTapName,
		AZ:              az,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(),
		State:           VTAP_STATE_PENDING,
		Lcuuid:          uuid.NewString(),
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerVTapByPodNode(db *gorm.DB) (*models.VTap, bool) {
	podNodeMgr := dbmgr.DBMgr[models.PodNode](db)
	podNodes, err := podNodeMgr.GetBatchFromIPs(r.hostIPs)
	if err != nil || len(podNodes) == 0 {
		podNodes, err = podNodeMgr.GetBatchFromName(r.host)
		if err != nil || len(podNodes) == 0 {
			return nil, false
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
	vmIDs := make([]int, 0, len(vmPodNodeConns))
	for _, conn := range vmPodNodeConns {
		vmIDToConn[conn.VMID] = conn
		vmIDs = append(vmIDs, conn.VMID)
	}

	vifMgr := dbmgr.DBMgr[models.VInterface](db)
	var matchVif *models.VInterface
	matchVif, err = vifMgr.GetVInterfaceFromDeviceIDs(
		r.ctrlMac,
		r.region,
		VIF_DEVICE_TYPE_POD_NODE,
		podNodeIDs)
	if err != nil {
		if len(vmIDs) > 0 {
			matchVif, err = vifMgr.GetVInterfaceFromDeviceIDs(
				r.ctrlMac,
				r.region,
				VIF_DEVICE_TYPE_VM,
				vmIDs)
			if err != nil {
				log.Errorf("vtap(%s) vinterface(%s) not found, err(%s)", r.ctrlIP, r.ctrlMac, err)
				return nil, false
			}
		} else {
			log.Errorf("vtap(%s) vinterface(%s) not found, err(%s)", r.ctrlIP, r.ctrlMac, err)
		}
	}
	var (
		matchPodNode *models.PodNode
		vTapType     int
	)
	if matchVif.DeviceType == VIF_DEVICE_TYPE_POD_NODE {
		matchPodNode = idToPodNode[matchVif.DeviceID]
		vTapType = VTAP_TYPE_POD_HOST
	} else {
		if conn, ok := vmIDToConn[matchVif.DeviceID]; ok {
			matchPodNode = idToPodNode[conn.PodNodeID]
			vTapType = VTAP_TYPE_POD_VM
		}
	}
	if matchPodNode == nil {
		log.Errorf("vtap(%s) pod_node not found", r.ctrlIP)
		return nil, false
	}
	vTapName := fmt.Sprintf("%s-P%d", matchPodNode.Name, matchPodNode.ID)
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vTapType,
		LaunchServer:    matchPodNode.IP,
		LaunchServerID:  matchPodNode.ID,
		Name:            vTapName,
		AZ:              matchPodNode.AZ,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(),
		State:           VTAP_STATE_PENDING,
		Lcuuid:          matchPodNode.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) getLanIPVIFIDs(db *gorm.DB) ([]int, map[int]string) {
	lanIPMgr := dbmgr.DBMgr[models.LANIP](db)
	lanIPs, err := lanIPMgr.GetBatchFromIPs(r.hostIPs)
	if err != nil || len(lanIPs) == 0 {
		log.Errorf("vtap(%s) vinterface_ip(%s) not found", r.ctrlIP, r.hostIPs)
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

func (r *VTapRegister) getWanIPVIFIDs(db *gorm.DB) ([]int, map[int]string) {
	wanIPs, err := dbmgr.DBMgr[models.WANIP](db).GetBatchFromIPs(r.hostIPs)
	if err != nil || len(wanIPs) == 0 {
		log.Errorf("vtap(%s) ip_resource(%s) not found", r.ctrlIP, r.hostIPs)
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

func (r *VTapRegister) registerMirrorVTapByIP(db *gorm.DB) (*models.VTap, bool) {
	vifIDs, _ := r.getWanIPVIFIDs(db)
	if vifIDs == nil {
		return nil, false
	}

	vifMgr := dbmgr.DBMgr[models.VInterface](db)
	vifs, err := vifMgr.GetBatchVInterfaceFromIDs(
		r.ctrlMac,
		r.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf("vtap(%s) vinterface(mac: %s, region: %s, devicetype: %d) not found",
			r.ctrlIP, r.ctrlMac, r.region, VIF_DEVICE_TYPE_VM)
		if err != nil {
			log.Error(err)
		}
		return nil, false
	}
	deviceIDs := make([]int, 0, len(vifs))
	deviceIDToVifID := make(map[int]int)
	for _, vif := range vifs {
		deviceIDs = append(deviceIDs, vif.DeviceID)
		deviceIDToVifID[vif.DeviceID] = vif.ID
	}
	vms, err := dbmgr.DBMgr[models.VM](db).GetBatchFromIDs(deviceIDs)
	if err != nil || len(vms) == 0 {
		log.Errorf("vtap(%s), vms(id=%s) not in DB", r.ctrlIP, deviceIDs)
		if err != nil {
			log.Error(err)
		}
		return nil, false
	}

	vmLaunchServers := make([]string, 0, len(vms))
	for _, vm := range vms {
		if vm.LaunchServer == "" {
			log.Errorf("vtap(%s), vm(id=%d) not launch server", r.ctrlIP, vm.ID)
			continue
		}
		if !Find[string](vmLaunchServers, vm.LaunchServer) {
			vmLaunchServers = append(vmLaunchServers, vm.LaunchServer)
		}
	}
	if len(vmLaunchServers) == 0 {
		return nil, false
	}
	host, err := dbmgr.DBMgr[models.Host](db).GetFirstFromBatchIPs(vmLaunchServers)
	if err != nil {
		log.Error("vtap(%s) host(%s) not found", r.ctrlIP, vmLaunchServers)
		return nil, false
	}
	vTapName := fmt.Sprintf("%s-H%d", host.Name, host.ID)
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            VTAP_TYPE_EXSI,
		LaunchServer:    host.IP,
		LaunchServerID:  host.ID,
		Name:            vTapName,
		AZ:              host.AZ,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(),
		State:           VTAP_STATE_PENDING,
		Lcuuid:          uuid.NewString(),
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerLocalVTapByIP(db *gorm.DB) (*models.VTap, bool) {
	vifIDs, vifIDToIP := r.getLanIPVIFIDs(db)
	if vifIDs == nil {
		vifIDs, vifIDToIP = r.getWanIPVIFIDs(db)
		if vifIDs == nil {
			return nil, false
		}
	}
	vifs, err := dbmgr.DBMgr[models.VInterface](db).GetBatchVInterfaceFromIDs(
		r.ctrlMac,
		r.region,
		VIF_DEVICE_TYPE_VM,
		vifIDs)
	if err != nil || len(vifs) == 0 {
		log.Errorf("vtap(%s) vinterface(mac: %s, region: %s, devicetype: %d) not found",
			r.ctrlIP, r.ctrlMac, r.region, VIF_DEVICE_TYPE_VM)
		if err != nil {
			log.Error(err)
		}
		return nil, false
	}
	deviceIDs := make([]int, 0, len(vifs))
	deviceIDToVifID := make(map[int]int)
	for _, vif := range vifs {
		deviceIDs = append(deviceIDs, vif.DeviceID)
		deviceIDToVifID[vif.DeviceID] = vif.ID
	}
	vm, err := dbmgr.DBMgr[models.VM](db).GetFirstFromBatchIDs(deviceIDs)
	if err != nil {
		log.Errorf("vtap(%s), vm(id=%s) not in DB, err: %s", r.ctrlIP, deviceIDs, err)
		return nil, false
	}
	var (
		vTapType     int
		launchServer string
	)
	if Find[int]([]int{VM_HTYPE_BM_C, VM_HTYPE_BM_N, VM_HTYPE_BM_S}, vm.HType) == true {
		vTapType = VTAP_TYPE_WORKLOAD_P
	} else {
		vTapType = VTAP_TYPE_WORKLOAD_V
	}
	if vifID, ok := deviceIDToVifID[vm.ID]; ok {
		launchServer = vifIDToIP[vifID]
	}
	vTapName := fmt.Sprintf("%s-W%d", vm.Name, vm.ID)
	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         r.ctrlMac,
		Type:            vTapType,
		LaunchServer:    launchServer,
		LaunchServerID:  vm.ID,
		Name:            vTapName,
		AZ:              vm.AZ,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(),
		State:           VTAP_STATE_PENDING,
		Lcuuid:          vm.Lcuuid,
	}
	result := r.insertToDB(dbVTap, db)
	return dbVTap, result
}

func (r *VTapRegister) registerVTapLocalTapMode(db *gorm.DB) *models.VTap {
	vtap, ok := r.registerVTapByHost(db)
	if ok == true {
		return vtap
	}
	vtap, ok = r.registerVTapByPodNode(db)
	if ok == true {
		return vtap
	}
	vtap, ok = r.registerLocalVTapByIP(db)
	if ok == true {
		return vtap
	}

	return nil
}

func (r *VTapRegister) registerVTapMirrorTapMode(db *gorm.DB) *models.VTap {
	vtap, ok := r.registerVTapByHost(db)
	if ok == true {
		return vtap
	}
	vtap, ok = r.registerVTapByPodNode(db)
	if ok == true {
		return vtap
	}
	vtap, ok = r.registerMirrorVTapByIP(db)
	if ok == true {
		return vtap
	}

	return nil
}

func (r *VTapRegister) registerVTapAnalyzerTapMode(db *gorm.DB) *models.VTap {
	az, err := dbmgr.DBMgr[models.AZ](db).GetFromRegion(r.region)
	if err != nil {
		log.Errorf("vtap(%s) no az in region %s", r.ctrlIP, r.region)
		return nil
	}

	dbVTap := &models.VTap{
		CtrlIP:          r.ctrlIP,
		CtrlMac:         "",
		Type:            VTAP_TYPE_DEDICATED,
		Name:            r.host,
		LaunchServer:    r.ctrlIP,
		AZ:              az.Lcuuid,
		VtapGroupLcuuid: r.getVTapGroupLcuuid(),
		State:           VTAP_STATE_PENDING,
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
	if trident.TapMode(r.tapMode) == trident.TapMode_LOCAL {
		vtap = r.registerVTapLocalTapMode(v.db)
	} else if trident.TapMode(r.tapMode) == trident.TapMode_MIRROR {
		vtap = r.registerVTapMirrorTapMode(v.db)
	} else if trident.TapMode(r.tapMode) == trident.TapMode_ANALYZER {
		vtap = r.registerVTapAnalyzerTapMode(v.db)
	} else {
		log.Errorf("unkown tap_mode (%d)", r.tapMode)
	}
	if vtap != nil {
		v.AddVTapCache(vtap)
		v.putChRegisterFisnish()
	}
}

func (r *VTapRegister) getKey() string {
	return r.ctrlIP + "-" + r.ctrlMac
}
