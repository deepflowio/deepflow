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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql" // FIXME: To avoid ambiguity, name the package either mysql_model or db_model.
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
)

var log = logging.MustGetLogger("trisolaris/vtap")

type VTapInfo struct {
	// key: ctrlIP+ctrlMac
	vTapCaches *VTapCacheMap
	// key: ID
	vtapIDCaches *VTapIDCacheMap
	// key: ctrlIP
	kvmVTapCaches *KvmVTapCacheMap

	metaData                       *metadata.MetaData
	config                         *config.Config
	vTapPlatformData               *VTapPlatformData
	groupData                      *GroupData
	vTapPolicyData                 *VTapPolicyData
	lcuuidToRegionID               map[string]int
	azToDomain                     map[string]string
	domainIdToLcuuid               map[int]string
	lcuuidToPodClusterID           map[string]int
	lcuuidToVPCID                  map[string]int
	hostIDToVPCID                  map[int]int
	hypervNetworkHostIds           mapset.Set
	vtapGroupShortIDToLcuuid       map[string]string
	vtapGroupLcuuidToConfiguration map[string]*VTapConfig
	vtapGroupLcuuidToLocalConfig   map[string]string
	vtapGroupLcuuidToEAHPEnabled   map[string]*int
	noVTapTapPortsMac              mapset.Set
	kvmVTapCtrlIPToTapPorts        map[string]mapset.Set
	kcData                         *KubernetesCluster
	isReady                        atomicbool.Bool // 缓存是否初始化完成
	realDefaultConfig              *VTapConfig     // 实际默认值配置
	pluginNameToUpdateTime         map[string]uint32

	// 配置改变重新生成平台数据
	isVTapChangedForPD atomicbool.Bool
	chVTapChangedForPD chan struct{}

	// 采集器变动重新生成remotesegment
	isVTapChangedForSegment atomicbool.Bool
	chVTapChangedForSegment chan struct{}

	// 触发重新生成采集器缓存
	chVTapCacheRefresh chan struct{}

	// 保存remote segment 只有专属采集器有，并且所有专属采集器数据一样
	remoteSegments []*trident.Segment

	// vtapregister
	registerMU        sync.Mutex
	register          map[string]*VTapRegister
	chVTapRegister    chan struct{}
	chRegisterSuccess chan struct{}

	vtaps            []*models.VTap
	db               *gorm.DB
	region           *string
	defaultVTapGroup *string

	vTapIPs *atomic.Value // []*trident.VtapIp

	localClusterID *string

	processInfo *ProcessInfo
	dbVTapIDs   mapset.Set

	ctx    context.Context
	cancel context.CancelFunc
	ORGID
}

func NewVTapInfo(db *gorm.DB, metaData *metadata.MetaData, cfg *config.Config, orgID int, pctx context.Context) *VTapInfo {
	ctx, cancel := context.WithCancel(pctx)
	vTapInfo := &VTapInfo{
		vTapCaches:                     NewVTapCacheMap(),
		vtapIDCaches:                   NewVTapIDCacheMap(),
		kvmVTapCaches:                  NewKvmVTapCacheMap(),
		metaData:                       metaData,
		groupData:                      newGroupData(metaData),
		vTapPolicyData:                 newVTapPolicyData(metaData),
		lcuuidToRegionID:               make(map[string]int),
		azToDomain:                     make(map[string]string),
		domainIdToLcuuid:               make(map[int]string),
		lcuuidToPodClusterID:           make(map[string]int),
		lcuuidToVPCID:                  make(map[string]int),
		hostIDToVPCID:                  make(map[int]int),
		hypervNetworkHostIds:           mapset.NewSet(),
		vtapGroupShortIDToLcuuid:       make(map[string]string),
		vtapGroupLcuuidToConfiguration: make(map[string]*VTapConfig),
		vtapGroupLcuuidToLocalConfig:   make(map[string]string),
		vtapGroupLcuuidToEAHPEnabled:   make(map[string]*int),
		noVTapTapPortsMac:              mapset.NewSet(),
		kvmVTapCtrlIPToTapPorts:        make(map[string]mapset.Set),
		pluginNameToUpdateTime:         make(map[string]uint32),
		kcData:                         newKubernetesCluster(db, metaData.ORGID),
		isReady:                        atomicbool.NewBool(false),
		isVTapChangedForPD:             atomicbool.NewBool(false),
		isVTapChangedForSegment:        atomicbool.NewBool(false),
		chVTapChangedForPD:             make(chan struct{}, 1),
		chVTapChangedForSegment:        make(chan struct{}, 1),
		chVTapCacheRefresh:             make(chan struct{}, 1),
		register:                       make(map[string]*VTapRegister),
		chVTapRegister:                 make(chan struct{}, 1),
		chRegisterSuccess:              make(chan struct{}, 1),
		db:                             db,
		config:                         cfg,
		vTapIPs:                        &atomic.Value{},
		dbVTapIDs:                      mapset.NewSet(),
		ORGID:                          ORGID(orgID),
		ctx:                            ctx,
		cancel:                         cancel,
	}

	vTapInfo.vTapPlatformData = newVTapPlatformData(orgID)
	vTapInfo.processInfo = NewProcessInfo(db, cfg, orgID)

	return vTapInfo
}

func (v *VTapInfo) AddVTapCache(vtap *models.VTap) {
	vTapCache := NewVTapCache(vtap, v)
	vTapCache.init()
	v.vTapPlatformData.setPlatformDataByVTap(v.metaData.GetPlatformDataOP(), vTapCache)
	vTapCache.setVTapLocalSegments(v.GenerateVTapLocalSegments(vTapCache))
	vTapCache.setVTapRemoteSegments(v.GetRemoteSegment(vTapCache))
	v.vTapCaches.Add(vTapCache)
	v.vtapIDCaches.Add(vTapCache)
	if vTapCache.GetVTapType() == VTAP_TYPE_KVM {
		v.kvmVTapCaches.Add(vTapCache)
	}
	log.Infof(v.Logf("add cache ctrl_ip: %s ctrl_mac: %s", vTapCache.GetCtrlIP(), vTapCache.GetCtrlMac()))
}

func (v *VTapInfo) GetVTapCache(key string) *VTapCache {
	if v == nil {
		return nil
	}
	return v.vTapCaches.Get(key)
}

func (v *VTapInfo) DeleteVTapCache(key string) {
	vTapCache := v.vTapCaches.Get(key)
	if vTapCache != nil {
		v.vTapCaches.Delete(key)
		v.vtapIDCaches.Delete(int(vTapCache.GetVTapID()))
		if vTapCache.GetVTapType() == VTAP_TYPE_KVM {
			v.kvmVTapCaches.Delete(vTapCache.GetCtrlIP())
		}
		log.Infof(v.Logf("delete cache vtap %s", key))
	}
}

func (v *VTapInfo) UpdateVTapCache(key string, vtap *models.VTap) {
	vTapCache := v.GetVTapCache(key)
	if vTapCache == nil {
		log.Error(v.Logf("vtap no cache. %s", key))
		return
	}
	vTapCache.updateVTapCacheFromDB(vtap)
}

func (v *VTapInfo) loadRegion() string {
	if v.config.NodeIP == "" {
		log.Error(v.Log("config NodeIP is null"))
		return ""
	}
	ctrlIP := v.config.NodeIP
	azConMgr := dbmgr.DBMgr[models.AZControllerConnection](v.db)
	azConn, err := azConMgr.GetFromControllerIP(ctrlIP)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Errorf(v.Logf("controller (%s) az connection not in DB", ctrlIP))
		return ""
	}

	v.region = proto.String(azConn.Region)
	return azConn.Region
}

func (v *VTapInfo) loadDefaultVTapGroup() string {
	defaultVTapGroup, err := dbmgr.DBMgr[models.VTapGroup](v.db).GetFromID(DEFAULT_VTAP_GROUP_ID)
	if err != nil {
		log.Errorf(v.Logf("no default vtap group, err(%s)", err))
		return ""
	}

	v.defaultVTapGroup = proto.String(defaultVTapGroup.Lcuuid)
	return defaultVTapGroup.Lcuuid
}

func (v *VTapInfo) loadVTapGroup() {
	vtapGroups, err := dbmgr.DBMgr[models.VTapGroup](v.db).Gets()
	if err != nil {
		log.Errorf(v.Logf("get vtap group failed, err(%s)", err))
		return
	}

	vtapGroupShortIDToLcuuid := make(map[string]string)
	for _, vtapGroup := range vtapGroups {
		vtapGroupShortIDToLcuuid[vtapGroup.ShortUUID] = vtapGroup.Lcuuid
	}

	v.vtapGroupShortIDToLcuuid = vtapGroupShortIDToLcuuid
}

func vtapPortToStr(port int64) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x",
		(port>>24)&0xff,
		(port>>16)&0xff,
		(port>>8)&0xff,
		port&0xff)
}

func (v *VTapInfo) loadAzData() {
	azToDomain := make(map[string]string)
	dbDataCache := v.metaData.GetDBDataCache()
	azs := dbDataCache.GetAZs()
	if azs != nil {
		for _, az := range azs {
			azToDomain[az.Lcuuid] = az.Domain
		}
	}
	lcuuidToRegionID := make(map[string]int)
	regions := dbDataCache.GetRegions()
	if regions != nil {
		for _, region := range regions {
			lcuuidToRegionID[region.Lcuuid] = region.ID
		}
	}
	v.azToDomain = azToDomain
	v.lcuuidToRegionID = lcuuidToRegionID
}

func (v *VTapInfo) loadDomainData() {
	domainIdToLcuuid := make(map[int]string)
	domains := v.metaData.GetDBDataCache().GetDomains()
	for _, domain := range domains {
		domainIdToLcuuid[domain.ID] = domain.Lcuuid
	}
	v.domainIdToLcuuid = domainIdToLcuuid
}

func (v *VTapInfo) loadDeviceData() {
	lcuuidToVPCID := make(map[string]int)
	hypervNetworkHostIds := mapset.NewSet()
	lcuuidToPodClusterID := make(map[string]int)
	dbDataCache := v.metaData.GetDBDataCache()
	hostDevices := dbDataCache.GetHostDevices()
	rawData := v.metaData.GetPlatformDataOP().GetRawData()
	hostIDToVifs := rawData.GetHostIDToVifs()
	idToNetwork := rawData.GetIDToNetwork()
	hostIDToVPCID := make(map[int]int)
	if hostDevices != nil {
		for _, hostDevice := range hostDevices {
			if hostDevice.Type == HOST_HTYPE_GATEWAY && hostDevice.HType == HOST_HTYPE_HYPER_V {
				hypervNetworkHostIds.Add(hostDevice.ID)
			}
			vifs, ok := hostIDToVifs[hostDevice.ID]
			if ok == false {
				continue
			}
			vpcID := 0
			for vif := range vifs.Iter() {
				hVif := vif.(*models.VInterface)
				if network, ok := idToNetwork[hVif.NetworkID]; ok {
					if vpcID < network.VPCID {
						vpcID = network.VPCID
					}
				}
			}
			hostIDToVPCID[hostDevice.ID] = vpcID
		}
	}
	vms := dbDataCache.GetVms()
	if vms != nil {
		for _, vm := range vms {
			lcuuidToVPCID[vm.Lcuuid] = vm.VPCID
		}
	}
	podNodes := dbDataCache.GetPodNodes()
	if podNodes != nil {
		for _, podNode := range podNodes {
			lcuuidToPodClusterID[podNode.Lcuuid] = podNode.PodClusterID
			lcuuidToVPCID[podNode.Lcuuid] = podNode.VPCID
		}
	}

	v.lcuuidToVPCID = lcuuidToVPCID
	v.hypervNetworkHostIds = hypervNetworkHostIds
	v.lcuuidToPodClusterID = lcuuidToPodClusterID
	v.hostIDToVPCID = hostIDToVPCID
}

func (v *VTapInfo) loadTapPortsData() {
	dbDataCache := v.metaData.GetDBDataCache()
	kvmVTapIdToCtrlIp := make(map[int]string)
	if v.vtaps != nil {
		for _, vtap := range v.vtaps {
			if vtap.Type == VTAP_TYPE_KVM {
				kvmVTapIdToCtrlIp[vtap.ID] = vtap.CtrlIP
			}
		}
	}
	noVTapTapPortsMac := mapset.NewSet()
	chVTapPorts := dbDataCache.GetChVTapPorts()
	kvmVTapCtrlIPToTapPorts := make(map[string]mapset.Set)
	if chVTapPorts != nil {
		for _, chVTapPort := range chVTapPorts {
			strPort := vtapPortToStr(chVTapPort.TapPort)
			if strPort == "" {
				continue
			}
			if chVTapPort.VTapID == 0 {
				noVTapTapPortsMac.Add(strPort)
				continue
			}
			vtapCtrlIP, ok := kvmVTapIdToCtrlIp[chVTapPort.VTapID]
			if ok {
				portSet, ok := kvmVTapCtrlIPToTapPorts[vtapCtrlIP]
				if ok {
					portSet.Add(strPort)
				} else {
					kvmVTapCtrlIPToTapPorts[vtapCtrlIP] = mapset.NewSet(strPort)
				}
			}
		}
	}

	v.noVTapTapPortsMac = noVTapTapPortsMac
	v.kvmVTapCtrlIPToTapPorts = kvmVTapCtrlIPToTapPorts
}

func (v *VTapInfo) loadPlugins() {
	pluginNameToUpdateTime := make(map[string]uint32)
	plugins, err := dbmgr.DBMgr[models.Plugin](v.db).GetFields([]string{"name", "updated_at"})
	if err != nil {
		log.Error(v.Logf("%s", err))
		return
	}
	for _, plugin := range plugins {
		pluginNameToUpdateTime[plugin.Name] = uint32(plugin.UpdatedAt.Unix())
	}
	v.pluginNameToUpdateTime = pluginNameToUpdateTime

}

func (v *VTapInfo) loadConfigData() {
	deafaultConfiguration := &agent_config.RAgentGroupConfigModel{}
	b, err := json.Marshal(DefaultVTapGroupConfig)
	if err == nil {
		err = json.Unmarshal(b, deafaultConfiguration)
		if err != nil {
			log.Error(v.Logf("%s", err))
		}
	} else {
		log.Error(v.Logf("%s", err))
	}

	v.realDefaultConfig = NewVTapConfig(deafaultConfiguration)
	dbDataCache := v.metaData.GetDBDataCache()
	configs := dbDataCache.GetAgentGroupConfigsFromDB(v.db)
	v.convertConfig(configs)
	v.loadPlugins()
}

func (v *VTapInfo) loadKubernetesCluster() {
	if v == nil {
		return
	}
	v.kcData.loadAndCheck(v.config.ClearKubernetesTime)
}

func (v *VTapInfo) loadVTaps() {
	vtaps, err := dbmgr.DBMgr[models.VTap](v.db).Gets()
	if err != nil {
		log.Error(v.Logf("%s", err))
	}
	v.vtaps = vtaps
}

func (v *VTapInfo) loadBaseData() {
	v.loadVTaps()
	v.loadAzData()
	v.loadDomainData()
	v.loadDeviceData()
	v.loadTapPortsData()
	v.loadConfigData()
	v.loadKubernetesCluster()
	v.loadRegion()
	v.loadDefaultVTapGroup()
	v.loadVTapGroup()
}

func isBlank(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.String:
		return value.Len() == 0
	case reflect.Bool:
		return !value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Ptr:
		if !value.IsNil() {
			rvalue := reflect.Indirect(value)
			if rvalue.Kind() == reflect.String {
				return rvalue.Len() == 0
			}
		}
		return value.IsNil()
	case reflect.Interface:
		return value.IsNil()
	}
	return reflect.DeepEqual(value.Interface(), reflect.Zero(value.Type()).Interface())
}

func JudgeField(field string) bool {
	for _, name := range []string{"ID", "VTapGroupLcuuid", "Lcuuid"} {
		if field == name {
			return true
		}
	}

	return false
}

func DefaultFieldNone(filed string) bool {
	for _, name := range []string{"CaptureBpf"} {
		if filed == name {
			return true
		}
	}

	return false
}

func (v *VTapInfo) convertConfig(configs []*agent_config.AgentGroupConfigModel) {
	if configs == nil {
		log.Error(v.Log("no vtap configs data"))
		return
	}

	vtapGroupLcuuidToConfiguration := make(map[string]*VTapConfig)
	vtapGroupLcuuidToLocalConfig := make(map[string]string)
	vtapGroupLcuuidToEAHPEnabled := make(map[string]*int)
	typeOfDefaultConfig := reflect.ValueOf(DefaultVTapGroupConfig).Elem()
	for _, config := range configs {
		if config.VTapGroupLcuuid == nil {
			continue
		}
		vtapGroupLcuuidToEAHPEnabled[*config.VTapGroupLcuuid] = config.ExternalAgentHTTPProxyEnabled
		if config.YamlConfig != nil {
			vtapGroupLcuuidToLocalConfig[*config.VTapGroupLcuuid] = *config.YamlConfig
		} else {
			vtapGroupLcuuidToLocalConfig[*config.VTapGroupLcuuid] = ""
		}
		tapConfiguration := &agent_config.AgentGroupConfigModel{}
		typeOfVTapConfiguration := reflect.ValueOf(tapConfiguration).Elem()
		tt := reflect.TypeOf(config).Elem()
		tv := reflect.ValueOf(config).Elem()
		for i := 0; i < tv.NumField(); i++ {
			field := tt.Field(i)
			if JudgeField(field.Name) == true {
				typeOfVTapConfiguration.Field(i).Set(tv.Field(i))
				continue
			}
			value := tv.Field(i)
			defaultValue := typeOfDefaultConfig.Field(i)
			if isBlank(value) == false {
				typeOfVTapConfiguration.Field(i).Set(value)
			} else {
				typeOfVTapConfiguration.Field(i).Set(defaultValue)
			}
		}
		// 转换结构体类型
		rtapConfiguration := &agent_config.RAgentGroupConfigModel{}
		b, err := json.Marshal(tapConfiguration)
		if err == nil {
			err = json.Unmarshal(b, rtapConfiguration)
			if err != nil {
				log.Error(v.Logf("%s", err))
			}
		} else {
			log.Error(v.Logf("%s", err))
		}

		vTapConfig := NewVTapConfig(rtapConfiguration)
		if config.VTapGroupLcuuid != nil {
			vtapGroupLcuuidToConfiguration[vTapConfig.VTapGroupLcuuid] = vTapConfig
		}
	}
	v.vtapGroupLcuuidToConfiguration = vtapGroupLcuuidToConfiguration
	v.vtapGroupLcuuidToLocalConfig = vtapGroupLcuuidToLocalConfig
	v.vtapGroupLcuuidToEAHPEnabled = vtapGroupLcuuidToEAHPEnabled
}

func (v *VTapInfo) GetVTapConfigFromShortID(shortID string) *VTapConfig {
	if v == nil {
		return nil
	}
	lcuuid, ok := v.vtapGroupShortIDToLcuuid[shortID]
	if ok == false {
		return nil
	}

	return v.vtapGroupLcuuidToConfiguration[lcuuid]
}

func (v *VTapInfo) GetVTapLocalConfig(vtapGroupLcuuid string) string {
	if v == nil {
		return ""
	}
	return v.vtapGroupLcuuidToLocalConfig[vtapGroupLcuuid]
}

func (v *VTapInfo) GetVTapLocalConfigByShortID(shortID string) string {
	if v == nil {
		return ""
	}
	lcuuid, ok := v.vtapGroupShortIDToLcuuid[shortID]
	if ok == false {
		return ""
	}

	return v.vtapGroupLcuuidToLocalConfig[lcuuid]
}

func (v *VTapInfo) GetDefaultMaxEscapeSeconds() int {
	return DefaultMaxEscapeSeconds
}

func (v *VTapInfo) GetDefaultMaxMemory() int {
	return DefaultMaxMemory
}

func (v *VTapInfo) GetVTapCacheIsReady() bool {
	if v == nil {
		return false
	}
	return v.isReady.IsSet()
}

func (v *VTapInfo) GetTapTypes() []*trident.TapType {
	if v == nil {
		return nil
	}
	return v.metaData.GetTapTypes()
}

func (v *VTapInfo) GetSkipInterface(c *VTapCache) []*trident.SkipInterface {
	if v == nil {
		return nil
	}
	if c.GetVTapType() == VTAP_TYPE_KVM {
		launchServer := c.GetLaunchServer()
		rawData := v.metaData.GetPlatformDataOP().GetRawData()
		if rawData != nil {
			return rawData.GetSkipInterface(launchServer)
		}
	}

	return nil
}

func (v *VTapInfo) GetContainers(vtapID int) []*trident.Container {
	if v == nil {
		return nil
	}
	rawData := v.metaData.GetPlatformDataOP().GetRawData()
	if rawData != nil {
		return rawData.GetContainers(vtapID)
	}

	return nil
}

func (v *VTapInfo) GetConfigTSDBIP() string {
	if v == nil {
		return ""
	}
	return v.config.TsdbIP
}

func (v *VTapInfo) GetSelfUpdateUrl() string {
	if v == nil {
		return ""
	}
	return v.config.SelfUpdateUrl
}

func (v *VTapInfo) GetTridentTypeForUnkonwVTap() uint16 {
	if v == nil {
		return 0
	}
	return v.config.TridentTypeForUnkonwVtap
}

func (v *VTapInfo) GetGroupData() []byte {
	if v == nil {
		return nil
	}
	return v.groupData.getGroupData()
}

func (v *VTapInfo) GetGroupDataVersion() uint64 {
	if v == nil {
		return 0
	}
	return v.groupData.getGroupDataVersion()
}

func (v *VTapInfo) GetVTapPolicyData(vtapID int, functions mapset.Set) []byte {
	if v == nil {
		return nil
	}
	return v.vTapPolicyData.getVTapPolicyData(vtapID, functions)
}

func (v *VTapInfo) GetVTapPolicyVersion(vtapID int, functions mapset.Set) uint64 {
	if v == nil {
		return 0
	}
	return v.vTapPolicyData.getVTapPolicyVersion(vtapID, functions)
}

func (v *VTapInfo) IsTheSameCluster(clusterID string) bool {
	if v == nil {
		return false
	}
	return v.getLocalClusterID() == clusterID
}

func GetKey(vtap *models.VTap) string {
	if vtap.CtrlMac == "" {
		return vtap.CtrlIP
	}
	return vtap.CtrlIP + "-" + vtap.CtrlMac
}

func (v *VTapInfo) updateVTapInfo() {
	dbKeyToVTap := make(map[string]*models.VTap)
	dbKeys := mapset.NewSet()
	dbVTapIDs := mapset.NewSet()
	if v.vtaps != nil {
		for _, vTap := range v.vtaps {
			key := GetKey(vTap)
			dbKeyToVTap[key] = vTap
			dbKeys.Add(key)
			dbVTapIDs.Add(vTap.ID)
		}
	}
	v.dbVTapIDs = dbVTapIDs
	cacheKeys := v.vTapCaches.GetKeySet()
	addVTaps := dbKeys.Difference(cacheKeys)
	delVTaps := cacheKeys.Difference(dbKeys)
	updateVTaps := dbKeys.Intersect(cacheKeys)
	for val := range addVTaps.Iter() {
		vTap, ok := dbKeyToVTap[val.(string)]
		if ok {
			v.AddVTapCache(vTap)
		}
		v.setVTapChangedForSegment()
	}

	for val := range delVTaps.Iter() {
		v.DeleteVTapCache(val.(string))
		v.setVTapChangedForSegment()
	}
	for val := range updateVTaps.Iter() {
		vtap, ok := dbKeyToVTap[val.(string)]
		if ok {
			v.UpdateVTapCache(val.(string), vtap)
		}
	}

	if v.isVTapChangedForPD.IsSet() {
		v.putChVTapChangedForPD()
		v.unsetVTapChangedForPD()
	}
	if v.isVTapChangedForSegment.IsSet() {
		v.putChVTapChangedForSegment()
		v.unsetVTapChangedForSegment()
	}
}

func (v *VTapInfo) GetKvmVTapCache(key string) *VTapCache {
	return v.kvmVTapCaches.Get(key)
}

func (v *VTapInfo) GetVTapIPs() []*trident.VtapIp {
	if v == nil {
		return nil
	}
	result, ok := v.vTapIPs.Load().([]*trident.VtapIp)
	if ok {
		return result
	}
	return nil
}

func (v *VTapInfo) updateVTapIPs(data []*trident.VtapIp) {
	v.vTapIPs.Store(data)
}

func (v *VTapInfo) generateVTapIP() {
	vTapIPs := make([]*trident.VtapIp, 0, v.vTapCaches.GetCount())
	cacheKeys := v.vTapCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheVTap := v.GetVTapCache(cacheKey)
		if cacheVTap == nil {
			continue
		}

		data := &trident.VtapIp{
			VtapId:       proto.Uint32(cacheVTap.GetVTapID()),
			EpcId:        proto.Uint32(uint32(cacheVTap.GetVPCID())),
			Ip:           proto.String(cacheVTap.GetLaunchServer()),
			PodClusterId: proto.Uint32(uint32(cacheVTap.GetPodClusterID())),
			TeamId:       proto.Uint32(uint32(cacheVTap.GetTeamID())),
			OrgId:        proto.Uint32(uint32(v.ORGID)),
		}
		vTapIPs = append(vTapIPs, data)
	}
	log.Debug(v.Logf("%s", vTapIPs))
	v.updateVTapIPs(vTapIPs)
}

func (v *VTapInfo) GetProcessInfo() *ProcessInfo {
	if v == nil {
		return nil
	}
	return v.processInfo
}

func (v *VTapInfo) GenerateVTapCache() {
	v.loadBaseData()
	v.updateVTapInfo()
	v.updateCacheToDB()
	v.generateVTapIP()
	v.generateLocalClusterID()
}

func (v *VTapInfo) UpdateTSDBVTapInfo(cVTaps []*trident.CommunicationVtap, tsdbIP string) {
	log.Debugf(v.Logf("tsdbIP: %s, vtaps: %s", tsdbIP, cVTaps))
	if v == nil {
		return
	}
	for _, cVTap := range cVTaps {
		vTapID := int(cVTap.GetVtapId())
		if vTapID == 0 {
			continue
		}
		vTapCache := v.vtapIDCaches.Get(vTapID)
		if vTapCache == nil {
			continue
		}
		lastTime := cVTap.GetLastActiveTime()
		if vTapCache.UpdateSyncedTSDB(time.Unix(int64(lastTime), 0), tsdbIP) {
			vTapCache.SetTSDBSyncFlag()
		}
	}
}

func (v *VTapInfo) IsCtrlMacInTapPorts(ctrlIP string, ctrlMac string) bool {
	tapPortSet, ok := v.kvmVTapCtrlIPToTapPorts[ctrlIP]
	if ok && tapPortSet.Contains(ctrlMac) {
		return true
	} else if v.noVTapTapPortsMac.Contains(ctrlMac) {
		return true
	}

	return false
}

func (v *VTapInfo) generateAllVTapPlatformData() {
	v.vTapPlatformData.clearPlatformDataTypeCache()
	platformDataOP := v.metaData.GetPlatformDataOP()
	cacheKeys := v.vTapCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheVTap := v.GetVTapCache(cacheKey)
		if cacheVTap == nil {
			continue
		}
		v.vTapPlatformData.setPlatformDataByVTap(platformDataOP, cacheVTap)
	}
	log.Debug(v.Logf("%s", v.vTapPlatformData))
}

func (v *VTapInfo) getLocalClusterID() string {
	if v.localClusterID != nil {
		return *v.localClusterID
	}

	return ""
}

func (v *VTapInfo) generateLocalClusterID() {
	if v.getLocalClusterID() == "" {
		clusterID, err := GetLocalClusterID()
		if err != nil {
			log.Error(v.Logf("%s", err))
			return
		}
		v.localClusterID = proto.String(clusterID)
		log.Infof(v.Logf("local cluster id: %s", v.getLocalClusterID()))
	}
}

func (v *VTapInfo) InitData() {
	v.loadBaseData()
	if v.vtaps != nil {
		for _, vtap := range v.vtaps {
			v.AddVTapCache(vtap)
		}
	} else {
		log.Error(v.Log("get vtap failed or no vtap data"))
	}
	log.Info(v.Log("init generate all vtap platform data"))
	// 最后生成romote segment
	v.generateAllVTapRemoteSegements()
	v.generateVTapIP()
	v.generateLocalClusterID()
	v.isReady.Set()
}

func (v *VTapInfo) generatePlatformDataAndSegment() {
	log.Info(v.Log("platform data changed generate all vtap platform data"))
	v.generateAllVTapPlatformData()
	log.Info(v.Log("platform data changed generate all vtap segment"))
	v.generateAllVTapSegements()
	pushmanager.Broadcast(int(v.ORGID))
}

func (v *VTapInfo) monitorDataChanged() {
	log.Info(v.Log("start monitor Data changed"))
	chDataChanged := v.metaData.GetPlatformDataOP().GetPlatformDataChangedCh()
	for {
		select {
		case <-chDataChanged:
			v.generatePlatformDataAndSegment()
		case <-v.chVTapChangedForPD:
			select {
			case <-chDataChanged:
				v.generatePlatformDataAndSegment()
			default:
				log.Info(v.Log("vtap config changed generate all vtap platform data "))
				v.generateAllVTapPlatformData()
				select {
				case <-v.chVTapChangedForSegment:
					log.Info(v.Log("vtap changed generate all vtap remote segment"))
					v.generateAllVTapRemoteSegements()
				default:
				}
			}
		case <-v.chVTapChangedForSegment:
			select {
			case <-chDataChanged:
				v.generatePlatformDataAndSegment()
			default:
				log.Info(v.Log("vtap changed generate all vtap remote segment"))
				v.generateAllVTapRemoteSegements()
				select {
				case <-v.chVTapChangedForPD:
					log.Info(v.Log("vtap config changed generate all vtap platform data "))
					v.generateAllVTapPlatformData()
				default:
				}
			}
		case <-v.ctx.Done():
			log.Info(v.Log("exit monitor data changed"))
			return
		}
	}
}

func (v *VTapInfo) getVTapPodDomains(c *VTapCache) []string {
	result := []string{}
	noPodDomains := []int{VTAP_TYPE_WORKLOAD_V, VTAP_TYPE_WORKLOAD_P}
	serverPodDomains := []int{VTAP_TYPE_ESXI, VTAP_TYPE_KVM, VTAP_TYPE_HYPER_V, VTAP_TYPE_HYPER_V_NETWORK}
	nodePodDomains := []int{VTAP_TYPE_POD_HOST, VTAP_TYPE_POD_VM}
	podDomains := mapset.NewSet()
	if Find[int](noPodDomains, c.GetVTapType()) {
		return result
	} else if Find[int](serverPodDomains, c.GetVTapType()) {
		rawData := v.metaData.GetPlatformDataOP().GetRawData()
		serverToVmIDs := rawData.GetServerToVmIDs()
		vmIDs := serverToVmIDs[c.GetLaunchServer()]
		if vmIDs == nil {
			return result
		}
		podNodeIDs := make([]int, 0, vmIDs.Cardinality())
		vmidToPodNodeID := rawData.GetVMIDToPodNodeID()
		for vmID := range vmIDs.Iter() {
			id := vmID.(int)
			podNodeID, ok := vmidToPodNodeID[id]
			if ok == false {
				continue
			}
			podNodeIDs = append(podNodeIDs, podNodeID)
		}
		for _, podNodeID := range podNodeIDs {
			podNode := rawData.GetPodNode(podNodeID)
			if podNode == nil {
				continue
			}
			if podNode.SubDomain == "" || podNode.Domain == podNode.SubDomain {
				podDomains.Add(podNode.Domain)
			} else {
				podDomains.Add(podNode.SubDomain)
			}
		}
	} else if Find[int](nodePodDomains, c.GetVTapType()) {
		rawData := v.metaData.GetPlatformDataOP().GetRawData()
		podNode := rawData.GetPodNode(c.GetLaunchServerID())
		if podNode == nil {
			log.Errorf(v.Logf("vtap(%s) not found launch_server pod_node(%s)", c.GetCtrlIP(), c.GetCtrlMac()))
			return result
		}
		if podNode.SubDomain == "" || podNode.Domain == podNode.SubDomain {
			podDomains.Add(podNode.Domain)
		} else {
			podDomains.Add(podNode.SubDomain)
		}
	} else if c.GetVTapType() == VTAP_TYPE_K8S_SIDECAR {
		rawData := v.metaData.GetPlatformDataOP().GetRawData()
		pod := rawData.GetPod(c.GetLaunchServerID())
		if pod != nil {
			podDomains.Add(pod.Domain)
		}
	}

	if podDomains.Cardinality() != 0 {
		for domain := range podDomains.Iter() {
			result = append(result, domain.(string))
		}
	}
	sort.Strings(result)

	return result
}

func (v *VTapInfo) GetKubernetesClusterID(clusterID string, value string, force bool) string {
	if v == nil {
		if force {
			return value
		}
		return ""
	}
	return v.kcData.getClusterID(clusterID, value, force)
}

func (v *VTapInfo) putChVTapChangedForPD() {
	select {
	case v.chVTapChangedForPD <- struct{}{}:
	default:
	}
}

func (v *VTapInfo) updateCacheToDB() {
	log.Info(v.Log("update vtap cache to db"))
	hostName := common.GetNodeName()
	if len(hostName) == 0 {
		log.Errorf(v.Log("hostname is null"))
		return
	}

	controllerMgr := dbmgr.DBMgr[models.Controller](v.db)
	options := controllerMgr.WithName(hostName)
	controller, err := controllerMgr.GetByOption(options)
	if err != nil {
		log.Errorf(v.Logf("no controller(%s) in DB", hostName))
		return
	}
	config := v.config
	if config.NodeIP == "" {
		log.Error(v.Log("config NodeIP is null"))
		return
	}
	hostIP := config.NodeIP
	updateVTaps := []*models.VTap{}
	keytoDBVTap := make(map[string]*models.VTap)

	dbVTaps, err := dbmgr.DBMgr[models.VTap](v.db).Gets()
	if err != nil {
		log.Error(v.Logf("get db vtap failed, %s", err))
		return
	}
	for _, vtap := range dbVTaps {
		keytoDBVTap[GetKey(vtap)] = vtap
	}
	cacheKeys := v.vTapCaches.List()
	for _, cacheKey := range cacheKeys {
		cacheVTap := v.GetVTapCache(cacheKey)
		if cacheVTap == nil {
			continue
		}
		dbVTap, ok := keytoDBVTap[cacheKey]
		if ok == false {
			continue
		}
		if dbVTap.Type == VTAP_TYPE_TUNNEL_DECAPSULATION {
		} else if controller.IP != dbVTap.ControllerIP &&
			!cacheVTap.controllerSyncFlag.IsSet() &&
			!cacheVTap.tsdbSyncFlag.IsSet() {
			continue
		}
		filterFlag := false
		var vtapSyncedControllerAt time.Time
		if cacheVTap.GetSyncedControllerAt() != nil {
			if dbVTap.SyncedControllerAt.IsZero() {
				vtapSyncedControllerAt = *cacheVTap.GetSyncedControllerAt()
				if dbVTap.Enable == VTAP_ENABLE_TRUE {
					dbVTap.SyncedControllerAt = vtapSyncedControllerAt
				}
			} else {
				vtapSyncedControllerAt = MaxTime(
					dbVTap.SyncedControllerAt,
					*cacheVTap.GetSyncedControllerAt())
				cacheVTap.UpdateSyncedControllerAt(vtapSyncedControllerAt)
				if dbVTap.Enable == VTAP_ENABLE_TRUE {
					dbVTap.SyncedControllerAt = vtapSyncedControllerAt
				}
			}
		} else if dbVTap.SyncedControllerAt.IsZero() {
			vtapSyncedControllerAt = dbVTap.SyncedControllerAt
		}

		if cacheVTap.controllerSyncFlag.IsSet() {
			dbVTap.Revision = cacheVTap.GetRevision()
			dbVTap.BootTime = cacheVTap.GetBootTime()
			dbVTap.CPUNum = cacheVTap.GetCPUNum()
			dbVTap.MemorySize = cacheVTap.GetMemorySize()
			dbVTap.Arch = cacheVTap.GetArch()
			dbVTap.Os = cacheVTap.GetOs()
			dbVTap.KernelVersion = cacheVTap.GetKernelVersion()
			dbVTap.ProcessName = cacheVTap.GetProcessName()
			dbVTap.CurrentK8sImage = cacheVTap.GetCurrentK8SImage()
			dbVTap.CtrlMac = cacheVTap.GetCtrlMac()
			dbVTap.RawHostname = cacheVTap.GetVTapRawHostname()
			cacheExceptions := cacheVTap.GetExceptions()
			tridentExceptions := uint64(VTAP_TRIDENT_EXCEPTIONS_MASK) & uint64(cacheExceptions)
			controllerException := uint64(VTAP_CONTROLLER_EXCEPTIONS_MASK) & uint64(dbVTap.Exceptions)
			dbVTap.Exceptions = int64(controllerException | tridentExceptions)
			cacheVTap.UpdateCurControllerIP(hostIP)
			dbVTap.CurControllerIP = cacheVTap.GetCurControllerIP()
			dbVTap.ExpectedRevision = cacheVTap.GetExpectedRevision()
			dbVTap.UpgradePackage = cacheVTap.GetUpgradePackage()
			filterFlag = true
		}

		if cacheVTap.tsdbSyncFlag.IsSet() {
			if cacheVTap.GetSyncedTSDBAt() != nil {
				if !dbVTap.SyncedAnalyzerAt.IsZero() {
					vtapSyncedTSDBAt := MaxTime(dbVTap.SyncedAnalyzerAt, *cacheVTap.GetSyncedTSDBAt())
					cacheVTap.UpdateSyncedTSDBAt(vtapSyncedTSDBAt)
					dbVTap.SyncedAnalyzerAt = vtapSyncedTSDBAt
				} else {
					vtapSyncedTSDBAt := *cacheVTap.GetSyncedTSDBAt()
					dbVTap.SyncedAnalyzerAt = vtapSyncedTSDBAt
				}
			}
			dbVTap.CurAnalyzerIP = cacheVTap.GetCurTSDBIP()
			filterFlag = true
		}

		cacheVTap.ResetControllerSyncFlag()
		cacheVTap.ResetTSDBSyncFlag()
		if (dbVTap.State != VTAP_STATE_PENDING && controller.IP == dbVTap.ControllerIP) || (dbVTap.Type == VTAP_TYPE_TUNNEL_DECAPSULATION && controller.NodeType == CONTROLLER_NODE_TYPE_MASTER) {
			now := time.Now()
			if now.Sub(cacheVTap.GetCachedAt()).Seconds() < float64(cacheVTap.GetConfigSyncInterval()*2) {
				// 如果时间差小于同步时间间隔，则认为刚启动,
				// 或新添加vtap，不进行状态更新
			} else if now.Sub(vtapSyncedControllerAt).Seconds() > float64(cacheVTap.GetConfigSyncInterval()*8) {
				if dbVTap.State != VTAP_STATE_NOT_CONNECTED {
					dbVTap.State = VTAP_STATE_NOT_CONNECTED
					filterFlag = true
					log.Infof(v.Logf("set vTap (%s) on (%s) to not connected", dbVTap.Name, dbVTap.LaunchServer))
				}
			} else if dbVTap.State == VTAP_STATE_NOT_CONNECTED {
				dbVTap.State = VTAP_STATE_NORMAL
				filterFlag = true
				log.Infof(v.Logf("set vTap (%s) on (%s) to normal", dbVTap.Name, dbVTap.LaunchServer))
			}
		}

		if filterFlag == true {
			updateVTaps = append(updateVTaps, dbVTap)
		}
	}
	vTapmgr := dbmgr.DBMgr[models.VTap](v.db)
	if len(updateVTaps) > 0 {
		log.Infof(v.Logf("update vtap count(%d)", len(updateVTaps)))
		err = vTapmgr.UpdateBulk(updateVTaps)
		if err != nil {
			log.Error(v.Logf("%s", err))
		}
	}
}

func (v *VTapInfo) setVTapChangedForPD() {
	v.isVTapChangedForPD.Set()
}

func (v *VTapInfo) unsetVTapChangedForPD() {
	v.isVTapChangedForPD.Unset()
}

func (v *VTapInfo) PutVTapCacheRefresh() {
	if v == nil {
		return
	}
	select {
	case v.chVTapCacheRefresh <- struct{}{}:
	default:
	}
}

func (v *VTapInfo) getRegion() string {
	if v.region != nil {
		return *v.region
	}

	return ""
}

func (v *VTapInfo) GetRegionIDByLcuuid(lcuuid string) int {
	if v == nil {
		return 0
	}
	return v.lcuuidToRegionID[lcuuid]
}

func (v *VTapInfo) getDefaultVTapGroup() string {
	if v == nil {
		return ""
	}
	if v.defaultVTapGroup != nil {
		return *v.defaultVTapGroup
	}

	return ""
}

func (v *VTapInfo) getDefaultTapMode() int {
	return v.config.DefaultTapMode
}

func (v *VTapInfo) getVTapAutoRegister() bool {
	return v.config.VTapAutoRegister
}

func (v *VTapInfo) Register(tapMode int, ctrlIP string, ctrlMac string,
	hostIPs []string, host string, vTapGroupID string, agentUniqueIdentifier int, teamID int) {
	vTapRegister := newVTapRegister(tapMode, ctrlIP, ctrlMac, hostIPs, host, vTapGroupID, agentUniqueIdentifier, v, teamID)
	v.registerMU.Lock()
	v.register[vTapRegister.getKey()] = vTapRegister
	v.registerMU.Unlock()
	select {
	case v.chVTapRegister <- struct{}{}:
	default:
	}
}

func (v *VTapInfo) putChRegisterFisnish() {
	select {
	case v.chRegisterSuccess <- struct{}{}:
	default:
	}
}

func (v *VTapInfo) StartRegister() {
	if v.loadRegion() == "" {
		log.Error(v.Logf("controller not found region"))
		return
	}
	if v.getDefaultVTapGroup() == "" {
		if v.loadDefaultVTapGroup() == "" {
			log.Error(v.Logf("controller not found default vtap group"))
			return
		}
	}
	v.registerMU.Lock()
	register := v.register
	v.register = make(map[string]*VTapRegister)
	v.registerMU.Unlock()
	var wg sync.WaitGroup
	for _, r := range register {
		wg.Add(1)
		go r.registerVTap(wg.Done)
	}
	wg.Wait()
}

func (v *VTapInfo) monitorVTapRegister() {
	for {
		select {
		case <-v.chVTapRegister:
			log.Info(v.Logf("start vtap register"))
			v.StartRegister()
			select {
			case <-v.chRegisterSuccess:
				v.putChVTapChangedForSegment()
			default:
			}
			log.Info(v.Logf("end vtap register"))
		case <-v.ctx.Done():
			log.Info(v.Log("exit monitor vtap Register"))
			return

		}
	}
}

func (v *VTapInfo) timedRefreshVTapCache() {
	interval := time.Duration(v.config.VTapCacheRefreshInterval)
	tickerVTapCache := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-tickerVTapCache:
			log.Info(v.Logf("start generate vtap cache data from timed"))
			v.GenerateVTapCache()
			v.processInfo.DeleteAgentExpiredData(v.dbVTapIDs)
			log.Info(v.Logf("end generate vtap cache data from timed"))
		case <-v.chVTapCacheRefresh:
			log.Info(v.Logf("start generate vtap cache data from rpc"))
			v.GenerateVTapCache()
			pushmanager.Broadcast(v.GetORGID())
			log.Info(v.Logf("end generate vtap cache data from rpc"))
		case <-v.ctx.Done():
			log.Info(v.Log("exit generate vtap cache data"))
			return
		}
	}
}

func (v *VTapInfo) TimedGenerateGPIDInfo() {
	v.processInfo.getDBData()
	interval := time.Duration(v.config.GPIDRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info(v.Log("start generate gpid data from timed"))
			v.processInfo.generateData()
			log.Info(v.Log("end generate gpid data from timed"))
		case <-v.ctx.Done():
			log.Info(v.Log("exit generate gpid data"))
			return
		}
	}
}

func (v *VTapInfo) Run() {
	v.InitData()
	go v.monitorDataChanged()
	go v.monitorVTapRegister()
	go v.TimedGenerateGPIDInfo()
	go v.timedRefreshVTapCache()
}

func (v *VTapInfo) stop() {
	v.cancel()
	log.Info(v.Log("exit vtap info generate"))
}
