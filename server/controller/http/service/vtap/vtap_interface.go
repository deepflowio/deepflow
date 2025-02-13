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
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
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

func (v *VTapInterface) getVIF(filter map[string]interface{}, fmtAndFilter func(*simplejson.Json, map[string]interface{}, *vpToolDataSet) []model.VTapInterface) ([]model.VTapInterface, error) {
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
	var azCConns []*mysqlmodel.AZControllerConnection
	v.db.Unscoped().Find(&azCConns)
	for _, c := range azCConns {
		controllerIPToRegionLcuuid[c.ControllerIP] = c.Region
	}
	var controllers []*mysqlmodel.Controller
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
	vtapVIFs = append(vtapVIFs, fmtAndFilter(masterRegionVVIFs, filter, toolDS)...)
	for slaveRegion, regionControllerIPs := range slaveRegionLcuuidToHealthyControllerIPs {
		log.Infof("get region (lcuuid: %s) vtap interfaces", slaveRegion, v.db.LogPrefixORGID)
		for _, ip := range regionControllerIPs {
			err := common.IsTCPActive(ip, common.GConfig.HTTPNodePort)
			if err != nil {
				log.Error(err.Error(), v.db.LogPrefixORGID)
			} else {
				vtapVIFs = append(vtapVIFs, fmtAndFilter(v.getRawVTapVinterfacesByRegion(ip, common.GConfig.HTTPNodePort, syncAPIQuery), filter, toolDS)...)
				break
			}
		}
	}
	return vtapVIFs, nil
}

func (v *VTapInterface) Get(filter map[string]interface{}) ([]model.VTapInterface, *response.Page, error) {
	data, err := v.getVIF(filter, v.fmtAndFilterForWeb)
	if err != nil {
		return nil, nil, err // TODO refactor
	}
	if filter["page_index"] == nil || filter["page_size"] == nil {
		return data, nil, nil
	}
	page := response.NewPage(filter["page_index"].(int), filter["page_size"].(int))
	if !page.IsValid() {
		return data, page, nil
	}
	start, end := page.Fill(len(data))
	return data[start:end], page, nil
}

func (v *VTapInterface) GetVIFResource(filter map[string]interface{}) ([]model.VTapInterface, error) {
	return v.getVIF(filter, v.fmtAndFilterForCH)
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
			log.Infof("no permission, drop all data", v.db.LogPrefixORGID)
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
	log.Infof("get vtap interfaces: %s", url, v.db.LogPrefixORGID)
	resp, err := common.CURLPerform(
		"GET",
		url,
		nil,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", v.userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", v.userInfo.ID)),
		common.WithHeader(common.HEADER_KEY_X_ORG_ID, fmt.Sprintf("%d", v.userInfo.ORGID)),
	)
	if err != nil {
		log.Errorf("get genesis vinterface failed: %s, %s", err.Error(), url, v.db.LogPrefixORGID)
		return simplejson.New()
	}
	if len(resp.Get("DATA").MustArray()) == 0 {
		log.Warning("no data in curl response", v.db.LogPrefixORGID)
		return simplejson.New()
	}
	return resp.Get("DATA")
}

func (v *VTapInterface) fmtAndFilterForWeb(vifs *simplejson.Json, filter map[string]interface{}, toolDS *vpToolDataSet) []model.VTapInterface {
	var vtapVIFs []model.VTapInterface
	filterName, hasName := filter["name"].(string)
	filterDeviceType, hasDeviceType := filter["device_type"].([]int)
	filterVTapType, hasVTapType := filter["vtap_type"].([]int)

	fuzzyName, hasFuzzyName := filter["fuzzy_name"].(string)
	fuzzyMac, hasFuzzyMac := filter["fuzzy_mac"].(string)
	fuzzyTapName, hasFuzzyTapName := filter["fuzzy_tap_name"].(string)
	fuzzyTapMAC, hasFuzzyTapMAC := filter["fuzzy_tap_mac"].(string)
	fuzzyDeviceName, hasFuzzyDeviceName := filter["fuzzy_device_name"].(string)
	fuzzyVTapName, hasFuzzyVTapName := filter["fuzzy_vtap_name"].(string)
	for i := range vifs.MustArray() {
		jVIF := vifs.GetIndex(i)
		name := jVIF.Get("NAME").MustString()
		if hasName && filterName != name {
			continue
		}

		if hasFuzzyName && ((name != "" && !strings.Contains(name, fuzzyName)) || name == "") {
			continue
		}
		mac := jVIF.Get("MAC").MustString()
		if hasFuzzyMac && ((mac != "" && !strings.Contains(mac, fuzzyMac)) || mac == "") {
			continue
		}
		tapName := jVIF.Get("TAP_NAME").MustString()
		if hasFuzzyTapName && ((tapName != "" && !strings.Contains(tapName, fuzzyTapName)) || tapName == "") {
			continue
		}
		tapMAC := jVIF.Get("TAP_MAC").MustString()
		if hasFuzzyTapMAC && ((tapMAC != "" && !strings.Contains(tapMAC, fuzzyTapMAC)) || tapMAC == "") {
			continue
		}

		vtapID := jVIF.Get("VTAP_ID").MustInt()
		lastSeen, err := time.Parse(time.RFC3339, jVIF.Get("LAST_SEEN").MustString())
		if err != nil {
			log.Errorf("parse time (%s) failed: %s", jVIF.Get("LAST_SEEN").MustString(), err.Error(), v.db.LogPrefixORGID)
		}
		vtapVIF := model.VTapInterface{
			ID:       jVIF.Get("ID").MustInt(),
			TeamID:   jVIF.Get("TEAM_ID").MustInt(),
			Name:     name,
			MAC:      mac,
			TapName:  tapName,
			TapMAC:   tapMAC,
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
			if hasVTapType && !slices.Contains(filterVTapType, vtapVIF.VTapType) {
				continue
			}
			if hasFuzzyVTapName && ((vtapVIF.VTapName != "" && !strings.Contains(vtapVIF.VTapName, fuzzyVTapName)) || vtapVIF.VTapName == "") {
				continue
			}

			macVIFs := toolDS.macToVIFs[vtapVIF.MAC]
			if len(macVIFs) > 0 {
				var macVIF *mysqlmodel.VInterface
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
						// Agent-owned resource
						macVIF = &mysqlmodel.VInterface{DeviceType: deviceType, DeviceID: vtapVIF.VTapLaunchServerID}
					}
				}
				vtapVIF.DeviceType = macVIF.DeviceType
				if hasDeviceType && !slices.Contains(filterDeviceType, vtapVIF.DeviceType) {
					continue
				}
				vtapVIF.DeviceID = macVIF.DeviceID

				switch vtapVIF.DeviceType {
				case common.VIF_DEVICE_TYPE_HOST:
					vtapVIF.DeviceName = toolDS.hostIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = vtapVIF.DeviceID
					vtapVIF.DeviceHostName = vtapVIF.DeviceName
				case common.VIF_DEVICE_TYPE_VM:
					if podNodeID, ok := toolDS.vmIDToPodNodeID[vtapVIF.DeviceID]; ok {
						vtapVIF.DeviceType = common.VIF_DEVICE_TYPE_POD_NODE
						vtapVIF.DeviceID = podNodeID
						vtapVIF.DeviceName = toolDS.podNodeIDToName[podNodeID]
						vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[podNodeID]
						vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
						vtapVIF.DevicePodNodeID = podNodeID
						vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[podNodeID]
					} else {
						vtapVIF.DeviceName = toolDS.vmIDToName[vtapVIF.DeviceID]
						vtapVIF.DeviceCHostID = vtapVIF.DeviceID
						vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceID]
					}
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[vtapVIF.DeviceID]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				case common.VIF_DEVICE_TYPE_POD_NODE:
					vtapVIF.DeviceName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[vtapVIF.DeviceID]]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
					vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[vtapVIF.DeviceID]
					vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
					vtapVIF.DevicePodNodeID = vtapVIF.DeviceID
					vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
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
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[toolDS.podIDToPodNodeID[vtapVIF.DeviceID]]]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
					vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[toolDS.podIDToPodNodeID[vtapVIF.DeviceID]]
					vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
					vtapVIF.DevicePodNodeID = toolDS.podIDToPodNodeID[vtapVIF.DeviceID]
					vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[vtapVIF.DevicePodNodeID]
				}
			}
		} else if vtapID != 0 {
			log.Errorf("vtap (%d) not found", vtapID, v.db.LogPrefixORGID)
		}
		if hasVTapType && !slices.Contains(filterVTapType, vtapVIF.VTapType) {
			continue
		}
		if hasDeviceType && !slices.Contains(filterDeviceType, vtapVIF.DeviceType) {
			continue
		}
		if hasFuzzyVTapName && ((vtapVIF.VTapName != "" && !strings.Contains(vtapVIF.VTapName, fuzzyVTapName)) || vtapVIF.VTapName == "") {
			continue
		}
		if hasFuzzyDeviceName && ((vtapVIF.DeviceName != "" && !strings.Contains(vtapVIF.DeviceName, fuzzyDeviceName)) || vtapVIF.DeviceName == "") {
			continue
		}
		vtapVIFs = append(vtapVIFs, vtapVIF)
	}
	return vtapVIFs
}

// get host, chost, pod_node by vtap
func (v *VTapInterface) fmtAndFilterForCH(vifs *simplejson.Json, filter map[string]interface{}, toolDS *vpToolDataSet) []model.VTapInterface {
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
			log.Errorf("parse time (%s) failed: %s", jVIF.Get("LAST_SEEN").MustString(), err.Error(), v.db.LogPrefixORGID)
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

			deviceType, ok := common.VTAP_TYPE_TO_DEVICE_TYPE[vtapVIF.VTapType]
			if !ok {
				continue
			}
			vtapVIF.DeviceType = deviceType
			vtapVIF.DeviceID = vtapVIF.VTapLaunchServerID
			switch vtapVIF.DeviceType {
			case common.VIF_DEVICE_TYPE_HOST:
				vtapVIF.DeviceName = toolDS.hostIDToName[vtapVIF.DeviceID]
				vtapVIF.DeviceHostID = vtapVIF.DeviceID
				vtapVIF.DeviceHostName = vtapVIF.DeviceName
			case common.VIF_DEVICE_TYPE_VM:
				if podNodeID, ok := toolDS.vmIDToPodNodeID[vtapVIF.DeviceID]; ok {
					vtapVIF.DeviceType = common.VIF_DEVICE_TYPE_POD_NODE
					vtapVIF.DeviceID = podNodeID
					vtapVIF.DeviceName = toolDS.podNodeIDToName[podNodeID]
					vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[podNodeID]
					vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
					vtapVIF.DevicePodNodeID = podNodeID
					vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[podNodeID]
				} else {
					vtapVIF.DeviceName = toolDS.vmIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceCHostID = vtapVIF.DeviceID
					vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceID]
				}
				vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[vtapVIF.DeviceID]]
				vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
			case common.VIF_DEVICE_TYPE_POD_NODE:
				vtapVIF.DeviceName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
				vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[vtapVIF.DeviceID]]]
				vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[vtapVIF.DeviceID]
				vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
				vtapVIF.DevicePodNodeID = vtapVIF.DeviceID
				vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
			case common.VIF_DEVICE_TYPE_POD:
				vtapVIF.DeviceName = toolDS.podIDToName[vtapVIF.DeviceID]
				vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[toolDS.podIDToPodNodeID[vtapVIF.DeviceID]]]]
				vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				vtapVIF.DeviceCHostID = toolDS.podNodeIDToVMID[toolDS.podIDToPodNodeID[vtapVIF.DeviceID]]
				vtapVIF.DeviceCHostName = toolDS.vmIDToName[vtapVIF.DeviceCHostID]
				vtapVIF.DevicePodNodeID = toolDS.podIDToPodNodeID[vtapVIF.DeviceID]
				vtapVIF.DevicePodNodeName = toolDS.podNodeIDToName[vtapVIF.DevicePodNodeID]
			}
		} else if vtapID != 0 {
			log.Errorf("vtap (%d) not found", vtapID, v.db.LogPrefixORGID)
		}
		vtapVIFs = append(vtapVIFs, vtapVIF)
	}
	return vtapVIFs
}

type vpToolDataSet struct {
	idToVTap              map[int]*mysqlmodel.VTap
	macToVIFs             map[string][]*mysqlmodel.VInterface
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
	podIDToPodNodeID      map[int]int
}

func newToolDataSet(db *mysql.DB) (toolDS *vpToolDataSet, err error) {
	toolDS = &vpToolDataSet{
		idToVTap:              make(map[int]*mysqlmodel.VTap),
		macToVIFs:             make(map[string][]*mysqlmodel.VInterface),
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
		podIDToPodNodeID:      make(map[int]int),
	}
	var vtaps []*mysqlmodel.VTap
	if err = db.Unscoped().Find(&vtaps).Error; err != nil {
		log.Error(dbQueryResourceFailed("vtap", err), db.LogPrefixORGID)
		return
	}
	for _, vtap := range vtaps {
		toolDS.idToVTap[vtap.ID] = vtap
	}

	var vifs []*mysqlmodel.VInterface
	if err = db.Select("mac", "deviceid", "devicetype").Unscoped().Find(&vifs).Error; err != nil {
		log.Error(dbQueryResourceFailed("vinterface", err), db.LogPrefixORGID)
		return
	}
	for _, vif := range vifs {
		toolDS.macToVIFs[vif.Mac] = append(toolDS.macToVIFs[vif.Mac], vif)
	}

	var hosts []*mysqlmodel.Host
	if err = db.Select("id", "name", "ip").Unscoped().Find(&hosts).Error; err != nil {
		log.Error(dbQueryResourceFailed("host_device", err), db.LogPrefixORGID)
		return
	}
	for _, host := range hosts {
		toolDS.hostIDToName[host.ID] = host.Name
		toolDS.hostIPToID[host.IP] = host.ID
	}

	var vms []*mysqlmodel.VM
	if err = db.Select("id", "name", "launch_server").Unscoped().Find(&vms).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm", err), db.LogPrefixORGID)
		return
	}
	for _, vm := range vms {
		toolDS.vmIDToName[vm.ID] = vm.Name
		toolDS.vmIDToLaunchServer[vm.ID] = vm.LaunchServer
	}

	var podNodes []*mysqlmodel.PodNode
	if err = db.Select("id", "name").Unscoped().Find(&podNodes).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod_node", err), db.LogPrefixORGID)
		return
	}
	for _, podNode := range podNodes {
		toolDS.podNodeIDToName[podNode.ID] = podNode.Name
	}

	var vmPodNodeConns []*mysqlmodel.VMPodNodeConnection
	if err = db.Unscoped().Find(&vmPodNodeConns).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm_pod_node_connection", err), db.LogPrefixORGID)
		return
	}
	for _, conn := range vmPodNodeConns {
		toolDS.vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		toolDS.podNodeIDToVMID[conn.PodNodeID] = conn.VMID
	}

	var vrouters []*mysqlmodel.VRouter
	if err = db.Select("id", "name").Unscoped().Find(&vrouters).Error; err != nil {
		log.Error(dbQueryResourceFailed("vrouter", err), db.LogPrefixORGID)
		return
	}
	for _, v := range vrouters {
		toolDS.vrouterIDToName[v.ID] = v.Name
	}

	var dhcpPorts []*mysqlmodel.DHCPPort
	if err = db.Select("id", "name").Unscoped().Find(&dhcpPorts).Error; err != nil {
		log.Error(dbQueryResourceFailed("dhcp_port", err), db.LogPrefixORGID)
		return
	}
	for _, d := range dhcpPorts {
		toolDS.dhcpPortIDToName[d.ID] = d.Name
	}

	var ngws []*mysqlmodel.NATGateway
	if err = db.Select("id", "name").Unscoped().Find(&ngws).Error; err != nil {
		log.Error(dbQueryResourceFailed("nat_gateway", err), db.LogPrefixORGID)
		return
	}
	for _, n := range ngws {
		toolDS.natGatewayIDToName[n.ID] = n.Name
	}

	var lbs []*mysqlmodel.LB
	if err = db.Select("id", "name").Unscoped().Find(&lbs).Error; err != nil {
		log.Error(dbQueryResourceFailed("lb", err), db.LogPrefixORGID)
		return
	}
	for _, lb := range lbs {
		toolDS.lbIDToName[lb.ID] = lb.Name
	}

	var rdsInstances []*mysqlmodel.RDSInstance
	if err = db.Select("id", "name").Unscoped().Find(&rdsInstances).Error; err != nil {
		log.Error(dbQueryResourceFailed("rds_instance", err), db.LogPrefixORGID)
		return
	}
	for _, r := range rdsInstances {
		toolDS.rdsInstanceIDToName[r.ID] = r.Name
	}

	var redisInstances []*mysqlmodel.RedisInstance
	if err = db.Select("id", "name").Unscoped().Find(&redisInstances).Error; err != nil {
		log.Error(dbQueryResourceFailed("redis_instance", err), db.LogPrefixORGID)
		return
	}
	for _, r := range redisInstances {
		toolDS.redisInstanceIDToName[r.ID] = r.Name
	}

	var podServices []*mysqlmodel.PodService
	if err = db.Select("id", "name").Unscoped().Find(&podServices).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod_service", err), db.LogPrefixORGID)
		return
	}
	for _, p := range podServices {
		toolDS.podServiceIDToName[p.ID] = p.Name
	}

	var pods []*mysqlmodel.Pod
	if err = db.Select("id", "name", "pod_node_id").Unscoped().Find(&pods).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod", err), db.LogPrefixORGID)
		return
	}
	for _, p := range pods {
		toolDS.podIDToName[p.ID] = p.Name
		toolDS.podIDToPodNodeID[p.ID] = p.PodNodeID
	}
	return
}
