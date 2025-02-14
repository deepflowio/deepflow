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
	"fmt"
	"net"
	"time"

	"github.com/bitly/go-simplejson"
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type VTapInterface struct {
	userInfo *httpcommon.UserInfo
	cfg      common.FPermit
	db       *mysql.DB
}

func NewVTapInterface(cfg common.FPermit, userInfo *httpcommon.UserInfo) *VTapInterface {
	return &VTapInterface{
		userInfo: userInfo,
		cfg:      cfg,
	}
}

func (v *VTapInterface) Get(filter map[string]interface{}) ([]model.VTapInterface, error) {
	// only super admin and admin can get vtap interfaces
	if v.userInfo.Type != common.USER_TYPE_SUPER_ADMIN && v.userInfo.Type != common.USER_TYPE_ADMIN {
		return []model.VTapInterface{}, nil
	}

	syncAPIQuery, dropAll, err := v.formatSyncAPIQuery(filter)
	if err != nil {
		return nil, err
	}
	if dropAll {
		return nil, nil
	}

	v.db, err = mysql.GetDB(v.userInfo.ORGID)
	if err != nil {
		log.Errorf("failed to get db for org: %d", v.userInfo.ORGID)
		return nil, err
	}
	toolDS, err := newToolDataSet(v.db)
	if err != nil {
		return nil, err
	}
	controllerIPToRegionLcuuid := make(map[string]string)
	var azCConns []*mysql.AZControllerConnection
	v.db.Unscoped().Find(&azCConns)
	for _, c := range azCConns {
		controllerIPToRegionLcuuid[c.ControllerIP] = c.Region
	}
	var controllers []*mysql.Controller
	v.db.Unscoped().Find(&controllers)
	slaveRegionLcuuidToHealthyControllerIPs := make(map[string][]string)
	for _, c := range controllers {
		if c.State == common.CONTROLLER_STATE_NORMAL && c.NodeType == common.CONTROLLER_NODE_TYPE_SLAVE {
			slaveRegionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]] = append(
				slaveRegionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]], c.IP,
			)
		}
	}

	masterRegionVVIFs := v.getRawVTapVinterfacesByRegion(common.LOCALHOST, common.GConfig.HTTPPort, syncAPIQuery)

	var vtapVIFs []model.VTapInterface
	vtapVIFs = append(vtapVIFs, v.formatVTapVInterfaces(masterRegionVVIFs, filter, toolDS)...)
	for slaveRegion, regionControllerIPs := range slaveRegionLcuuidToHealthyControllerIPs {
		log.Info(v.db.Logf("get region (lcuuid: %s) vtap interfaces", slaveRegion))
		for _, ip := range regionControllerIPs {
			err := common.IsTCPActive(ip, common.GConfig.HTTPNodePort)
			if err != nil {
				log.Error(err.Error())
			} else {
				vtapVIFs = append(vtapVIFs, v.formatVTapVInterfaces(v.getRawVTapVinterfacesByRegion(ip, common.GConfig.HTTPNodePort, syncAPIQuery), filter, toolDS)...)
				break
			}
		}
	}
	return vtapVIFs, nil
}

func (v *VTapInterface) formatSyncAPIQuery(filter map[string]interface{}) (queryStr string, dropAll bool, err error) {
	if v.userInfo.Type == common.USER_TYPE_SUPER_ADMIN {
		if teamID, ok := filter["team_id"]; ok {
			return fmt.Sprintf("team_id_filter=whitelist&team_id=%s", teamID), false, nil
		}
		return "", false, nil
	}

	unauthorizedTeamIDs, err := httpcommon.GetUnauthorizedTeamIDs(v.userInfo, &v.cfg)
	if err != nil {
		return "", true, err
	}
	if _, ok := filter["team_id"]; ok {
		teamID, _ := filter["team_id"].(int)
		if _, ok := unauthorizedTeamIDs[teamID]; ok {
			log.Info(v.db.Logf("no permission, drop all data"))
			return "", true, nil
		}
		return fmt.Sprintf("team_id_filter=whitelist&team_id=%s", teamID), false, nil
	}

	if len(unauthorizedTeamIDs) == 0 {
		return "", false, nil
	}

	queryTeamIDs := "team_id_filter=blacklist"
	for teamID := range unauthorizedTeamIDs {
		queryTeamIDs += fmt.Sprintf("&team_id=%d", teamID)
	}
	return queryTeamIDs, false, nil
}

func (v *VTapInterface) getRawVTapVinterfacesByRegion(host string, port int, queryStr string) *simplejson.Json {
	url := fmt.Sprintf("http://%s/v1/sync/vinterface/", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if queryStr != "" {
		url += "?" + queryStr
	}
	log.Info(v.db.Logf("get vtap interfaces: %s", url))
	resp, err := common.CURLPerform(
		"GET",
		url,
		nil,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", v.userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", v.userInfo.ID)),
		common.WithHeader(common.HEADER_KEY_X_ORG_ID, fmt.Sprintf("%d", v.userInfo.ORGID)),
	)
	if err != nil {
		log.Error(v.db.Logf("get genesis vinterface failed: %s, %s", err.Error(), url))
		return simplejson.New()
	}
	if len(resp.Get("DATA").MustArray()) == 0 {
		log.Warning(v.db.Logf("no data in curl response"))
		return simplejson.New()
	}
	return resp.Get("DATA")
}

func (v *VTapInterface) formatVTapVInterfaces(vifs *simplejson.Json, filter map[string]interface{}, toolDS *vpToolDataSet) []model.VTapInterface {
	var vtapVIFs []model.VTapInterface
	for i := range vifs.MustArray() {
		jVIF := vifs.GetIndex(i)
		name := jVIF.Get("NAME").MustString()
		if n, ok := filter["name"]; ok {
			if n != name {
				continue
			}
		}
		vtapID := jVIF.Get("VTAP_ID").MustInt()
		lastSeen, err := time.Parse(time.RFC3339, jVIF.Get("LAST_SEEN").MustString())
		if err != nil {
			log.Error(v.db.Logf("parse time (%s) failed: %s", jVIF.Get("LAST_SEEN").MustString(), err.Error()))
		}
		vtapVIF := model.VTapInterface{
			ID:       jVIF.Get("ID").MustInt(),
			TeamID:   jVIF.Get("TEAM_ID").MustInt(),
			Name:     name,
			MAC:      jVIF.Get("MAC").MustString(),
			TapName:  jVIF.Get("TAP_NAME").MustString(),
			TapMAC:   jVIF.Get("TAP_MAC").MustString(),
			VTapID:   vtapID,
			HostIP:   jVIF.Get("HOST_IP").MustString(),
			NodeIP:   jVIF.Get("NODE_IP").MustString(),
			LastSeen: lastSeen.Format(common.GO_BIRTHDAY),
		}
		vtap, ok := toolDS.idToVTap[vtapID]
		if ok {
			vtapVIF.VTapLaunchServer = vtap.LaunchServer
			vtapVIF.VTapLaunchServerID = vtap.LaunchServerID
			vtapVIF.VTapType = vtap.Type
			vtapVIF.VTapName = vtap.Name

			macVIFs := toolDS.macToVIFs[vtapVIF.MAC]
			if len(macVIFs) > 0 {
				var macVIF *mysql.VInterface
				if len(macVIFs) == 1 {
					macVIF = macVIFs[0]
				} else {
					// 仅当mac属于host、vm或pod node时，会可能有多个vif，此时需使用与采集器类型匹配的设备类型的vif
					deviceType, ok := common.VTAP_TYPE_TO_DEVICE_TYPE[vtapVIF.VTapType]
					if ok {
						for _, mv := range macVIFs {
							if mv.DeviceType == deviceType {
								// When the mac is the same, select the vinterface of the same vpc
								if slices.Contains([]int{common.VTAP_TYPE_WORKLOAD_V, common.VTAP_TYPE_WORKLOAD_P, common.VTAP_TYPE_POD_HOST, common.VTAP_TYPE_POD_VM}, vtapVIF.VTapType) {
									if mv.DeviceID == vtapVIF.VTapLaunchServerID {
										macVIF = mv
										break
									}
								} else {
									macVIF = mv
									break
								}
								// Compatible with pod_node and VM related scenarios
							} else if mv.DeviceType == common.VIF_DEVICE_TYPE_VM && deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
								if _, ok := toolDS.vmIDToPodNodeID[mv.DeviceID]; ok {
									macVIF = mv
									break
								}
							}
						}
					}
					if macVIF == nil {
						log.Warning(v.db.Logf("vif with mac: %s not found", vtapVIF.MAC))
						continue
					}
				}
				vtapVIF.DeviceType = macVIF.DeviceType
				vtapVIF.DeviceID = macVIF.DeviceID

				switch vtapVIF.DeviceType {
				case common.VIF_DEVICE_TYPE_HOST:
					vtapVIF.DeviceName = toolDS.hostIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_VM:
					vtapVIF.DeviceName = toolDS.vmIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[vtapVIF.DeviceID]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
					if podNodeID, ok := toolDS.vmIDToPodNodeID[vtapVIF.DeviceID]; ok {
						vtapVIF.DeviceType = common.VIF_DEVICE_TYPE_POD_NODE
						vtapVIF.DeviceID = podNodeID
						vtapVIF.DeviceName = toolDS.podNodeIDToName[podNodeID]
					}
				case common.VIF_DEVICE_TYPE_POD_NODE:
					vtapVIF.DeviceName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[vtapVIF.DeviceID]]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				case common.VIF_DEVICE_TYPE_VROUTER:
					vtapVIF.DeviceName = toolDS.vrouterIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_DHCP_PORT:
					vtapVIF.DeviceName = toolDS.dhcpPortIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_NAT_GATEWAY:
					vtapVIF.DeviceName = toolDS.natGatewayIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_LB:
					vtapVIF.DeviceName = toolDS.lbIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_RDS_INSTANCE:
					vtapVIF.DeviceName = toolDS.rdsInstanceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_REDIS_INSTANCE:
					vtapVIF.DeviceName = toolDS.redisInstanceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_POD_SERVICE:
					vtapVIF.DeviceName = toolDS.podServiceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_POD:
					vtapVIF.DeviceName = toolDS.podIDToName[vtapVIF.DeviceID]
				}
			}
		} else if vtapID != 0 {
			log.Error(v.db.Logf("vtap (%d) not found", vtapID))
		}
		vtapVIFs = append(vtapVIFs, vtapVIF)
	}
	return vtapVIFs
}

type vpToolDataSet struct {
	idToVTap              map[int]*mysql.VTap
	macToVIFs             map[string][]*mysql.VInterface
	hostIDToName          map[int]string
	hostIPToID            map[string]int
	vmIDToName            map[int]string
	vmIDToLaunchServer    map[int]string
	podNodeIDToName       map[int]string
	vmIDToPodNodeID       map[int]int
	podNodeIDToVMID       map[int]int
	dhcpPortIDToName      map[int]string
	vrouterIDToName       map[int]string
	natGatewayIDToName    map[int]string
	lbIDToName            map[int]string
	rdsInstanceIDToName   map[int]string
	redisInstanceIDToName map[int]string
	podServiceIDToName    map[int]string
	podIDToName           map[int]string
}

func newToolDataSet(db *mysql.DB) (toolDS *vpToolDataSet, err error) {
	toolDS = &vpToolDataSet{
		idToVTap:              make(map[int]*mysql.VTap),
		macToVIFs:             make(map[string][]*mysql.VInterface),
		hostIDToName:          make(map[int]string),
		hostIPToID:            make(map[string]int),
		vmIDToName:            make(map[int]string),
		vmIDToLaunchServer:    make(map[int]string),
		podNodeIDToName:       make(map[int]string),
		vmIDToPodNodeID:       make(map[int]int),
		podNodeIDToVMID:       make(map[int]int),
		vrouterIDToName:       make(map[int]string),
		dhcpPortIDToName:      make(map[int]string),
		natGatewayIDToName:    make(map[int]string),
		lbIDToName:            make(map[int]string),
		rdsInstanceIDToName:   make(map[int]string),
		redisInstanceIDToName: make(map[int]string),
		podServiceIDToName:    make(map[int]string),
		podIDToName:           make(map[int]string),
	}
	var vtaps []*mysql.VTap
	if err = db.Unscoped().Find(&vtaps).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("vtap", err)))
		return
	}
	for _, vtap := range vtaps {
		toolDS.idToVTap[vtap.ID] = vtap
	}

	var vifs []*mysql.VInterface
	if err = db.Select("mac", "deviceid", "devicetype").Unscoped().Find(&vifs).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("vinterface", err)))
		return
	}
	for _, vif := range vifs {
		toolDS.macToVIFs[vif.Mac] = append(toolDS.macToVIFs[vif.Mac], vif)
	}

	var hosts []*mysql.Host
	if err = db.Select("id", "name").Unscoped().Find(&hosts).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("host_device", err)))
		return
	}
	for _, host := range hosts {
		toolDS.hostIDToName[host.ID] = host.Name
		toolDS.hostIPToID[host.IP] = host.ID
	}

	var vms []*mysql.VM
	if err = db.Select("id", "name", "launch_server").Unscoped().Find(&vms).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("vm", err)))
		return
	}
	for _, vm := range vms {
		toolDS.vmIDToName[vm.ID] = vm.Name
		toolDS.vmIDToLaunchServer[vm.ID] = vm.LaunchServer
	}

	var podNodes []*mysql.PodNode
	if err = db.Select("id", "name").Unscoped().Find(&podNodes).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("pod_node", err)))
		return
	}
	for _, podNode := range podNodes {
		toolDS.podNodeIDToName[podNode.ID] = podNode.Name
	}

	var vmPodNodeConns []*mysql.VMPodNodeConnection
	if err = db.Unscoped().Find(&vmPodNodeConns).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("vm_pod_node_connection", err)))
		return
	}
	for _, conn := range vmPodNodeConns {
		toolDS.vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		toolDS.podNodeIDToVMID[conn.PodNodeID] = conn.VMID
	}

	var vrouters []*mysql.VRouter
	if err = db.Select("id", "name").Unscoped().Find(&vrouters).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("vrouter", err)))
		return
	}
	for _, v := range vrouters {
		toolDS.vrouterIDToName[v.ID] = v.Name
	}

	var dhcpPorts []*mysql.DHCPPort
	if err = db.Select("id", "name").Unscoped().Find(&dhcpPorts).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("dhcp_port", err)))
		return
	}
	for _, d := range dhcpPorts {
		toolDS.dhcpPortIDToName[d.ID] = d.Name
	}

	var ngws []*mysql.NATGateway
	if err = db.Select("id", "name").Unscoped().Find(&ngws).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("nat_gateway", err)))
		return
	}
	for _, n := range ngws {
		toolDS.natGatewayIDToName[n.ID] = n.Name
	}

	var lbs []*mysql.LB
	if err = db.Select("id", "name").Unscoped().Find(&lbs).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("lb", err)))
		return
	}
	for _, lb := range lbs {
		toolDS.lbIDToName[lb.ID] = lb.Name
	}

	var rdsInstances []*mysql.RDSInstance
	if err = db.Select("id", "name").Unscoped().Find(&rdsInstances).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("rds_instance", err)))
		return
	}
	for _, r := range rdsInstances {
		toolDS.rdsInstanceIDToName[r.ID] = r.Name
	}

	var redisInstances []*mysql.RedisInstance
	if err = db.Select("id", "name").Unscoped().Find(&redisInstances).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("redis_instance", err)))
		return
	}
	for _, r := range redisInstances {
		toolDS.redisInstanceIDToName[r.ID] = r.Name
	}

	var podServices []*mysql.PodService
	if err = db.Select("id", "name").Unscoped().Find(&podServices).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("pod_service", err)))
		return
	}
	for _, p := range podServices {
		toolDS.podServiceIDToName[p.ID] = p.Name
	}

	var pods []*mysql.Pod
	if err = db.Select("id", "name").Unscoped().Find(&pods).Error; err != nil {
		log.Error(db.Log(dbQueryResourceFailed("pod", err)))
		return
	}
	for _, p := range pods {
		toolDS.podIDToName[p.ID] = p.Name
	}
	return
}
