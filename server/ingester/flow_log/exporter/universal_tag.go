/*
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

package exporter

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

type UniversalTags struct {
	Region       string
	AZ           string
	Host         string
	L3DeviceType string
	L3Device     string
	PodNode      string
	PodNS        string
	PodGroup     string
	Pod          string
	PodCluster   string
	L3Epc        string
	Subnet       string
	Service      string
	GProcess     string
	Vtap         string

	CHost      string
	Router     string
	DhcpGW     string
	PodService string
	Redis      string
	RDS        string
	LB         string
	NatGW      string

	TapPortName string
}

type Tag uint8

const (
	REGION Tag = iota
	AZ
	HOST
	L3_DEVICE_TYPE
	L3_DEVICE
	POD_NODE
	POD_NS
	POD_GROUP
	POD
	POD_CLUSTER
	L3_EPC
	SUBNET
	SERVICE
	GPROCESS
	VTAP
	MAX_TAG_MAP_ID
)

var TagTableNames = []string{
	REGION:         "region_map",
	AZ:             "az_map",
	HOST:           "",
	L3_DEVICE_TYPE: "node_type_map",
	L3_DEVICE:      "device_map",
	POD_NODE:       "pod_node_map",
	POD_NS:         "pod_ns_map",
	POD_GROUP:      "pod_group_map",
	POD:            "pod_map",
	POD_CLUSTER:    "pod_cluster_map",
	L3_EPC:         "l3_epc_map",
	SUBNET:         "subnet_map",
	SERVICE:        "",
	GPROCESS:       "gprocess_map",
	VTAP:           "vtap_map",
}

const (
	TYPE_INTERNET       = 0
	TYPE_VM             = 1
	TYPE_VROUTER        = 5
	TYPE_HOST           = 6
	TYPE_DHCP_PORT      = 9
	TYPE_POD            = 10
	TYPE_POD_SERVICE    = 11
	TYPE_REDIS_INSTANCE = 12
	TYPE_RDS_INSTANCE   = 13
	TYPE_POD_NODE       = 14
	TYPE_LB             = 15
	TYPE_NAT_GATEWAY    = 16
	TYPE_POD_GROUP      = 101
	TYPE_SERVICE        = 102
	TYPE_GPROCESS       = 120
	TYPE_IP             = 255
)

func (t Tag) TableName() string {
	return TagTableNames[t]
}

type UniversalTagMaps [MAX_TAG_MAP_ID]map[uint32]string

func (u *UniversalTagsManager) QueryUniversalTags(l7FlowLog *log_data.L7FlowLog) (*UniversalTags, *UniversalTags) {
	tagMaps := u.universalTagMaps
	tapPortName := u.tapPortNameMap[uint64(l7FlowLog.VtapID)<<32|uint64(l7FlowLog.TapPort)]
	return &UniversalTags{
			Region:       tagMaps[REGION][uint32(l7FlowLog.RegionID0)],
			AZ:           tagMaps[AZ][uint32(l7FlowLog.AZID0)],
			Host:         tagMaps[L3_DEVICE][uint32(TYPE_HOST)<<24|uint32(l7FlowLog.HostID0)],
			L3DeviceType: tagMaps[L3_DEVICE_TYPE][uint32(l7FlowLog.L3DeviceType0)],
			L3Device:     tagMaps[L3_DEVICE][uint32(l7FlowLog.L3DeviceID0)],
			PodNode:      tagMaps[POD_NODE][uint32(l7FlowLog.PodNodeID0)],
			PodNS:        tagMaps[POD_NS][uint32(l7FlowLog.PodNSID0)],
			PodGroup:     tagMaps[POD_GROUP][uint32(l7FlowLog.PodGroupID0)],
			Pod:          tagMaps[POD][uint32(l7FlowLog.PodID0)],
			PodCluster:   tagMaps[POD_CLUSTER][uint32(l7FlowLog.PodClusterID0)],
			L3Epc:        tagMaps[L3_EPC][uint32(l7FlowLog.L3EpcID0)],
			Subnet:       tagMaps[SUBNET][uint32(l7FlowLog.SubnetID0)],
			Service:      tagMaps[L3_DEVICE][uint32(uint32(TYPE_SERVICE)<<24|l7FlowLog.ServiceID0)],
			GProcess:     tagMaps[GPROCESS][uint32(l7FlowLog.GPID0)],
			Vtap:         tagMaps[VTAP][uint32(l7FlowLog.VtapID)],

			CHost:      tagMaps[L3_DEVICE][uint32(TYPE_VM)<<24|uint32(l7FlowLog.L3DeviceID0)],
			Router:     tagMaps[L3_DEVICE][uint32(TYPE_VROUTER)<<24|uint32(l7FlowLog.L3DeviceID0)],
			DhcpGW:     tagMaps[L3_DEVICE][uint32(TYPE_DHCP_PORT)<<24|uint32(l7FlowLog.L3DeviceID0)],
			PodService: tagMaps[L3_DEVICE][uint32(TYPE_POD_SERVICE)<<24|uint32(l7FlowLog.L3DeviceID0)],
			Redis:      tagMaps[L3_DEVICE][uint32(TYPE_REDIS_INSTANCE)<<24|uint32(l7FlowLog.L3DeviceID0)],
			RDS:        tagMaps[L3_DEVICE][uint32(TYPE_RDS_INSTANCE)<<24|uint32(l7FlowLog.L3DeviceID0)],
			LB:         tagMaps[L3_DEVICE][uint32(TYPE_LB)<<24|uint32(l7FlowLog.L3DeviceID0)],

			TapPortName: tapPortName,
		}, &UniversalTags{
			Region:       tagMaps[REGION][uint32(l7FlowLog.RegionID1)],
			AZ:           tagMaps[AZ][uint32(l7FlowLog.AZID1)],
			Host:         tagMaps[L3_DEVICE][uint32(TYPE_HOST)<<24|uint32(l7FlowLog.HostID1)],
			L3DeviceType: tagMaps[L3_DEVICE_TYPE][uint32(l7FlowLog.L3DeviceType1)],
			L3Device:     tagMaps[L3_DEVICE][uint32(l7FlowLog.L3DeviceID1)],
			PodNode:      tagMaps[POD_NODE][uint32(l7FlowLog.PodNodeID1)],
			PodNS:        tagMaps[POD_NS][uint32(l7FlowLog.PodNSID1)],
			PodGroup:     tagMaps[POD_GROUP][uint32(l7FlowLog.PodGroupID1)],
			Pod:          tagMaps[POD][uint32(l7FlowLog.PodID1)],
			PodCluster:   tagMaps[POD_CLUSTER][uint32(l7FlowLog.PodClusterID1)],
			L3Epc:        tagMaps[L3_EPC][uint32(l7FlowLog.L3EpcID1)],
			Subnet:       tagMaps[SUBNET][uint32(l7FlowLog.SubnetID1)],
			Service:      tagMaps[L3_DEVICE][uint32(TYPE_SERVICE<<24)|l7FlowLog.ServiceID1],
			GProcess:     tagMaps[GPROCESS][uint32(l7FlowLog.GPID1)],
			Vtap:         tagMaps[VTAP][uint32(l7FlowLog.VtapID)],

			CHost:      tagMaps[L3_DEVICE][uint32(TYPE_VM)<<24|uint32(l7FlowLog.L3DeviceID1)],
			Router:     tagMaps[L3_DEVICE][uint32(TYPE_VROUTER)<<24|uint32(l7FlowLog.L3DeviceID1)],
			DhcpGW:     tagMaps[L3_DEVICE][uint32(TYPE_DHCP_PORT)<<24|uint32(l7FlowLog.L3DeviceID1)],
			PodService: tagMaps[L3_DEVICE][uint32(TYPE_POD_SERVICE)<<24|uint32(l7FlowLog.L3DeviceID1)],
			Redis:      tagMaps[L3_DEVICE][uint32(TYPE_REDIS_INSTANCE)<<24|uint32(l7FlowLog.L3DeviceID1)],
			RDS:        tagMaps[L3_DEVICE][uint32(TYPE_RDS_INSTANCE)<<24|uint32(l7FlowLog.L3DeviceID1)],
			LB:         tagMaps[L3_DEVICE][uint32(TYPE_LB)<<24|uint32(l7FlowLog.L3DeviceID1)],

			TapPortName: tapPortName,
		}
}

func (u *UniversalTagsManager) QueryCustomK8sLabels(podID uint32) Labels {
	return u.podIDLabelsMap[podID]
}

type Labels map[string]string

type UniversalTagsManager struct {
	config           *config.Config
	universalTagMaps *UniversalTagMaps
	tapPortNameMap   map[uint64]string
	podIDLabelsMap   map[uint32]Labels
	k8sLabelsRegexp  *regexp.Regexp

	connection *sql.DB
}

func NewUniversalTagsManager(config *config.Config) *UniversalTagsManager {
	universalTagMaps := &UniversalTagMaps{}
	for i := range universalTagMaps {
		universalTagMaps[i] = make(map[uint32]string)
	}
	var k8sLabelsRegexp *regexp.Regexp
	if config.Exporter.ExportCustomK8sLabelsRegexp != "" {
		var err error
		k8sLabelsRegexp, err = regexp.Compile(config.Exporter.ExportCustomK8sLabelsRegexp)
		if err != nil {
			log.Warningf("OTLP exporter compile k8s label regexp pattern failed: %s", err)
		}
	}
	return &UniversalTagsManager{
		config:           config,
		universalTagMaps: universalTagMaps,
		tapPortNameMap:   make(map[uint64]string),
		podIDLabelsMap:   make(map[uint32]Labels),
		k8sLabelsRegexp:  k8sLabelsRegexp,
	}
}

func (u *UniversalTagsManager) Start() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if newTags, err := u.GetUniversalTagMaps(); err == nil {
			for i := REGION; i < MAX_TAG_MAP_ID; i++ {
				if newTags[i] != nil {
					u.universalTagMaps[i] = newTags[i]
				}
				if u.universalTagMaps[i] == nil {
					u.universalTagMaps[i] = make(map[uint32]string)
				}
			}
		} else {
			log.Warningf("update universall tag maps faile: %s", err)
			continue
		}

		if newTapPortMap, err := u.queryTapPortMap(); err == nil {
			if newTapPortMap != nil {
				u.tapPortNameMap = newTapPortMap
			}
		}

		if newPodIdLabelsMap, err := u.queryPodIdLabelsMap(); err == nil {
			if len(newPodIdLabelsMap) != 0 {
				u.podIDLabelsMap = newPodIdLabelsMap
			}
		}
	}
}

func (u *UniversalTagsManager) checkOrResetConnect() error {
	var err error
	if u.connection == nil {
		u.connection, err = common.NewCKConnection(u.config.Base.CKDB.ActualAddrs[0], u.config.Base.CKDBAuth.Username, u.config.Base.CKDBAuth.Password)
		if err != nil {
			return err
		}
		return nil
	}
	if err := u.connection.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			log.Warningf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		u.connection.Close()
		u.connection = nil
		return err
	}
	return nil
}

func (u *UniversalTagsManager) GetUniversalTagMaps() (*UniversalTagMaps, error) {
	if err := u.checkOrResetConnect(); err != nil {
		return nil, err
	}
	tagMaps := &UniversalTagMaps{}
	var m map[uint32]string
	var err error
	for i := REGION; i < MAX_TAG_MAP_ID; i++ {
		if i == L3_DEVICE_TYPE {
			m, err = u.queryNodeTypeMap()
		} else if i == L3_DEVICE {
			m, err = u.queryDeviceMap()
		} else {
			m, err = u.queryMap(i.TableName())
		}
		if err == nil {
			tagMaps[i] = m
		}
	}

	return tagMaps, nil
}

func (u *UniversalTagsManager) queryIDName(sql string) (map[uint32]string, error) {
	m := make(map[uint32]string)
	rows, err := u.connection.Query(sql)
	if err != nil {
		log.Warning(err)
		return nil, err
	}
	var id uint64
	var name string
	for rows.Next() {
		err := rows.Scan(&id, &name)
		if err != nil {
			log.Warning(err)
			return nil, err
		}
		m[uint32(id)] = name
	}
	return m, err
}

func (u *UniversalTagsManager) queryMap(tableName string) (map[uint32]string, error) {
	if tableName == "" {
		return nil, fmt.Errorf("table is empty")
	}
	sql := fmt.Sprintf("SELECT id,name FROM flow_tag.`%s`", tableName)
	return u.queryIDName(sql)
}

func (u *UniversalTagsManager) queryNodeTypeMap() (map[uint32]string, error) {
	sql := fmt.Sprintf("SELECT resource_type,node_type FROM flow_tag.`node_type_map`")
	return u.queryIDName(sql)
}

func (u *UniversalTagsManager) queryDeviceMap() (map[uint32]string, error) {
	sql := fmt.Sprintf("SELECT devicetype,deviceid,name FROM flow_tag.`device_map`")
	m := make(map[uint32]string)
	rows, err := u.connection.Query(sql)
	if err != nil {
		log.Warning(err)
		return nil, err
	}
	var dtype, id uint64
	var name string
	for rows.Next() {
		err := rows.Scan(&dtype, &id, &name)
		if err != nil {
			log.Warning(err)
			return nil, err
		}
		m[uint32((dtype<<24)|id)] = name
	}
	return m, err
}

func (u *UniversalTagsManager) queryTapPortMap() (map[uint64]string, error) {
	sql := fmt.Sprintf("SELECT vtap_id,tap_port,name FROM flow_tag.`vtap_port_map`")
	m := make(map[uint64]string)
	rows, err := u.connection.Query(sql)
	if err != nil {
		log.Warning(err)
		return nil, err
	}
	var vtapId, tapPort uint64
	var name string
	for rows.Next() {
		err := rows.Scan(&vtapId, &tapPort, &name)
		if err != nil {
			log.Warning(err)
			return nil, err
		}
		m[vtapId<<32|tapPort] = name
	}
	return m, err
}

func (u *UniversalTagsManager) isK8sLabelExport(name string) bool {
	// if not configured, all are not exported
	if len(u.config.Exporter.ExportCustomK8sLabelsRegexp) == 0 {
		return false
	}

	if u.k8sLabelsRegexp != nil && u.k8sLabelsRegexp.MatchString(name) {
		return true
	}

	return false
}

func (u *UniversalTagsManager) queryPodIdLabelsMap() (map[uint32]Labels, error) {
	sql := fmt.Sprintf("SELECT id,key,value FROM flow_tag.`pod_k8s_label_map`")
	m := make(map[uint32]Labels)
	rows, err := u.connection.Query(sql)
	if err != nil {
		log.Warning(err)
		return nil, err
	}
	var podId uint64
	var key, value string
	for rows.Next() {
		err := rows.Scan(&podId, &key, &value)
		if err != nil {
			log.Warning(err)
			return nil, err
		}
		if !u.isK8sLabelExport(key) {
			continue
		}
		if labels, ok := m[uint32(podId)]; ok {
			labels[key] = value
		} else {
			m[uint32(podId)] = map[string]string{key: value}
		}
	}
	return m, err
}
