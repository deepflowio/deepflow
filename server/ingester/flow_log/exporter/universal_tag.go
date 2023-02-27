package exporter

import (
	"database/sql"
	"fmt"
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
	HOST_TYPE    = 6
	SERVICE_TYPE = 11
)

func (t Tag) TableName() string {
	return TagTableNames[t]
}

type UniversalTagMaps [MAX_TAG_MAP_ID]map[uint32]string

func (u *UniversalTagsManager) QueryUniversalTags(l7FlowLog *log_data.L7FlowLog) (*UniversalTags, *UniversalTags) {
	tagMaps := u.universalTagMaps
	return &UniversalTags{
			Region:       tagMaps[REGION][uint32(l7FlowLog.RegionID0)],
			AZ:           tagMaps[AZ][uint32(l7FlowLog.AZID0)],
			Host:         tagMaps[HOST][uint32(HOST_TYPE)<<24|uint32(l7FlowLog.HostID0)],
			L3DeviceType: tagMaps[L3_DEVICE_TYPE][uint32(l7FlowLog.L3DeviceType0)],
			L3Device:     tagMaps[L3_DEVICE][uint32(l7FlowLog.L3DeviceID0)],
			PodNode:      tagMaps[POD_NODE][uint32(l7FlowLog.PodNodeID0)],
			PodNS:        tagMaps[POD_NS][uint32(l7FlowLog.PodNSID0)],
			PodGroup:     tagMaps[POD_GROUP][uint32(l7FlowLog.PodGroupID0)],
			Pod:          tagMaps[POD][uint32(l7FlowLog.PodID0)],
			PodCluster:   tagMaps[POD_CLUSTER][uint32(l7FlowLog.PodClusterID0)],
			L3Epc:        tagMaps[L3_EPC][uint32(l7FlowLog.L3EpcID0)],
			Subnet:       tagMaps[SUBNET][uint32(l7FlowLog.SubnetID0)],
			Service:      tagMaps[L3_DEVICE][uint32(uint32(SERVICE_TYPE)<<24|l7FlowLog.ServiceID0)],
			GProcess:     tagMaps[GPROCESS][uint32(l7FlowLog.GPID0)],
			Vtap:         tagMaps[VTAP][uint32(l7FlowLog.VtapID)],
		}, &UniversalTags{
			Region:       tagMaps[REGION][uint32(l7FlowLog.RegionID1)],
			AZ:           tagMaps[AZ][uint32(l7FlowLog.AZID1)],
			Host:         tagMaps[L3_DEVICE][uint32(HOST_TYPE)<<24|uint32(l7FlowLog.HostID1)],
			L3DeviceType: tagMaps[L3_DEVICE_TYPE][uint32(l7FlowLog.L3DeviceType1)],
			L3Device:     tagMaps[L3_DEVICE][uint32(l7FlowLog.L3DeviceID1)],
			PodNode:      tagMaps[POD_NODE][uint32(l7FlowLog.PodNodeID1)],
			PodNS:        tagMaps[POD_NS][uint32(l7FlowLog.PodNSID1)],
			PodGroup:     tagMaps[POD_GROUP][uint32(l7FlowLog.PodGroupID1)],
			Pod:          tagMaps[POD][uint32(l7FlowLog.PodID1)],
			PodCluster:   tagMaps[POD_CLUSTER][uint32(l7FlowLog.PodClusterID1)],
			L3Epc:        tagMaps[L3_EPC][uint32(l7FlowLog.L3EpcID1)],
			Subnet:       tagMaps[SUBNET][uint32(l7FlowLog.SubnetID1)],
			Service:      tagMaps[L3_DEVICE][uint32(SERVICE_TYPE<<24)|l7FlowLog.ServiceID1],
			GProcess:     tagMaps[GPROCESS][uint32(l7FlowLog.GPID1)],
			Vtap:         tagMaps[VTAP][uint32(l7FlowLog.VtapID)],
		}
}

type UniversalTagsManager struct {
	config           *config.Config
	universalTagMaps *UniversalTagMaps
	connection       *sql.DB
}

func NewUniversalTagsManager(config *config.Config) *UniversalTagsManager {
	universalTagMaps := &UniversalTagMaps{}
	for i := range universalTagMaps {
		universalTagMaps[i] = make(map[uint32]string)
	}
	return &UniversalTagsManager{
		config:           config,
		universalTagMaps: universalTagMaps,
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
