package vtap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"

	. "server/controller/common"
	models "server/controller/db/mysql"
	. "server/controller/trisolaris/common"
	"server/controller/trisolaris/config"
	"server/controller/trisolaris/dbmgr"
	"server/controller/trisolaris/metadata"
	"server/controller/trisolaris/pushmanager"
	. "server/controller/trisolaris/utils"
	"server/controller/trisolaris/utils/atomicbool"
)

var log = logging.MustGetLogger("trisolaris/vtap")

var LOCAL_FILE_VTAP = []int{
	VTAP_TYPE_POD_VM,
	VTAP_TYPE_POD_HOST,
	VTAP_TYPE_EXSI,
	VTAP_TYPE_DEDICATED,
	VTAP_TYPE_TUNNEL_DECAPSULATION,
}

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
	azToRegion                     map[string]string
	azToDomain                     map[string]string
	domainIdToLcuuid               map[int]string
	lcuuidToPodClusterID           map[string]int
	lcuuidToVPCID                  map[string]int
	hostIDToVPCID                  map[int]int
	hypervNetworkHostIds           mapset.Set
	vtapGroupLcuuidToConfiguration map[string]*VTapConfig
	vtapLcuuidToConfigFile         map[string]*models.VTapConfigFile
	noVTapTapPortsMac              mapset.Set
	kvmVTapCtrlIPToTapPorts        map[string]mapset.Set
	kcData                         *KubernetesCluster
	isReady                        atomicbool.Bool                // 缓存是否初始化完成
	dbDefaultConfig                *models.VTapGroupConfiguration // 数据库默认配置
	dbGlobalConfig                 *models.VTapGroupConfiguration // 数据库全局配置
	realDefaultConfig              *VTapConfig                    // 实际默认值配置

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
}

func NewVTapInfo(db *gorm.DB, metaData *metadata.MetaData, cfg *config.Config) *VTapInfo {
	return &VTapInfo{
		vTapCaches:                     NewVTapCacheMap(),
		vtapIDCaches:                   NewVTapIDCacheMap(),
		kvmVTapCaches:                  NewKvmVTapCacheMap(),
		metaData:                       metaData,
		vTapPlatformData:               newVTapPlatformData(),
		azToRegion:                     make(map[string]string),
		azToDomain:                     make(map[string]string),
		domainIdToLcuuid:               make(map[int]string),
		lcuuidToPodClusterID:           make(map[string]int),
		lcuuidToVPCID:                  make(map[string]int),
		hostIDToVPCID:                  make(map[int]int),
		hypervNetworkHostIds:           mapset.NewSet(),
		vtapGroupLcuuidToConfiguration: make(map[string]*VTapConfig),
		vtapLcuuidToConfigFile:         make(map[string]*models.VTapConfigFile),
		noVTapTapPortsMac:              mapset.NewSet(),
		kvmVTapCtrlIPToTapPorts:        make(map[string]mapset.Set),
		kcData:                         newKubernetesCluster(db),
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
	}
}

func (v *VTapInfo) AddVTapCache(vtap *models.VTap) {
	vTapCache := NewVTapCache(vtap)
	vTapCache.init(v)
	v.vTapPlatformData.setPlatformDataByVTap(v.metaData.GetPlatformDataOP(), vTapCache)
	vTapCache.setVTapLocalSegments(v.GenerateVTapLocalSegments(vTapCache))
	vTapCache.setVTapRemoteSegments(v.GetRemoteSegment(vTapCache))
	v.vTapCaches.Add(vTapCache)
	v.vtapIDCaches.Add(vTapCache)
	if vTapCache.GetVTapType() == VTAP_TYPE_KVM {
		v.kvmVTapCaches.Add(vTapCache)
	}
	log.Infof("add cache ctrl_ip: %s ctrl_mac: %s", vTapCache.GetCtrlIP(), vTapCache.GetCtrlMac())
}

func (v *VTapInfo) GetVTapCache(key string) *VTapCache {
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
		log.Infof("delete cache vtap %s", key)
	}
}

func (v *VTapInfo) UpdateVTapCache(key string, vtap *models.VTap) {
	vTapCache := v.GetVTapCache(key)
	if vTapCache == nil {
		log.Error("vtap no cache. ", key)
		return
	}
	vTapCache.updateVTapCacheFromDB(vtap, v)
}

func (v *VTapInfo) loadRegion() string {
	if len(v.config.MasterControllerNetIPs) == 0 {
		log.Error("master-controller-ips is empty")
		return ""
	}
	ctrlIP := ""
	masterIP := v.config.MasterControllerNetIPs[0]
	if ip, err := Lookup(masterIP); err == nil {
		ctrlIP = ip.String()
	} else {
		log.Error(err, "lookup controller ip failed", masterIP)
		return ""
	}

	azConMgr := dbmgr.DBMgr[models.AZControllerConnection](v.db)
	azConn, err := azConMgr.GetFromControllerIP(ctrlIP)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Errorf("controller (%s) az connection not in DB", ctrlIP)
		return ""
	}

	v.region = proto.String(azConn.Region)
	return azConn.Region
}

func (v *VTapInfo) loadDefaultVTapGroup() string {
	defaultVTapGroup, err := dbmgr.DBMgr[models.VTapGroup](v.db).GetFromID(DEFAULT_VTAP_GROUP_ID)
	if err != nil {
		log.Error("no default vtap group, err(%s)", err)
		return ""
	}

	v.defaultVTapGroup = proto.String(defaultVTapGroup.Lcuuid)
	return defaultVTapGroup.Lcuuid
}

func vtapPortToStr(port int64) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x",
		(port>>24)&0xff,
		(port>>16)&0xff,
		(port>>8)&0xff,
		port&0xff)
}

func (v *VTapInfo) loadAzData() {
	azToRegion := make(map[string]string)
	azToDomain := make(map[string]string)
	dbDataCache := v.metaData.GetDBDataCache()
	azs := dbDataCache.GetAZs()
	if azs != nil {
		for _, az := range azs {
			azToRegion[az.Lcuuid] = az.Region
			azToDomain[az.Lcuuid] = az.Domain
		}
	}
	v.azToRegion = azToRegion
	v.azToDomain = azToDomain
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
			for vif := range vifs.Iter() {
				hVif := vif.(*models.VInterface)
				if network, ok := idToNetwork[hVif.NetworkID]; ok {
					hostIDToVPCID[hostDevice.ID] = network.VPCID
					break
				}
			}
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

func (v *VTapInfo) loadConfigData() {
	dbDataCache := v.metaData.GetDBDataCache()
	configs := dbDataCache.GetVTapGroupConfigurationsFromDB(v.db)
	if configs != nil {
		for _, config := range configs {
			if config.ID == -1 {
				v.dbDefaultConfig = config
				continue
			}
			if config.VTapGroupLcuuid == nil {
				v.dbGlobalConfig = config
				continue
			}
			if v.dbDefaultConfig != nil && v.dbGlobalConfig != nil {
				break
			}
		}
	}
	v.convertConfig(configs)

	vtapLcuuidToConfigFile := make(map[string]*models.VTapConfigFile)
	vtapConfigFiles := dbDataCache.GetVTapConfigFilesFromDB(v.db)
	if vtapConfigFiles != nil {
		for _, configFile := range vtapConfigFiles {
			vtapLcuuidToConfigFile[configFile.VTapLcuuid] = configFile
		}
	}
	v.vtapLcuuidToConfigFile = vtapLcuuidToConfigFile
}

func (v *VTapInfo) loadKubernetesCluster() {
	v.kcData.loadAndCheck(v.config.ClearKubernetesTime)
}

func (v *VTapInfo) loadVTaps() {
	vtaps, err := dbmgr.DBMgr[models.VTap](v.db).Gets()
	if err != nil {
		log.Error(err)
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

func (v *VTapInfo) convertConfig(configs []*models.VTapGroupConfiguration) {
	if configs == nil {
		log.Error("no vtap configs data")
		return
	}
	if v.dbDefaultConfig == nil || v.dbGlobalConfig == nil {
		log.Error("no defaultconfig data or no gloablconfig data")
		return
	}

	vtapGroupLcuuidToConfiguration := make(map[string]*VTapConfig)
	typeOfDefaultConfig := reflect.ValueOf(v.dbDefaultConfig).Elem()
	typeOfGlobalConfig := reflect.ValueOf(v.dbGlobalConfig).Elem()
	for _, config := range configs {
		if config.ID == -1 {
			continue
		}
		tapConfiguration := &models.VTapGroupConfiguration{}
		typeOfVTapConfiguration := reflect.ValueOf(tapConfiguration).Elem()
		tt := reflect.TypeOf(config).Elem()
		tv := reflect.ValueOf(config).Elem()
		for i := 0; i < tv.NumField(); i++ {
			field := tt.Field(i)
			if field.Name == "YamlConfig" {
				continue
			}
			if JudgeField(field.Name) == true {
				typeOfVTapConfiguration.Field(i).Set(tv.Field(i))
				continue
			}
			value := tv.Field(i)
			defaultValue := typeOfDefaultConfig.Field(i)
			globalValue := typeOfGlobalConfig.Field(i)
			if isBlank(value) == false {
				typeOfVTapConfiguration.Field(i).Set(value)
			} else if isBlank(globalValue) == false {
				typeOfVTapConfiguration.Field(i).Set(globalValue)
			} else if DefaultFieldNone(field.Name) || isBlank(defaultValue) == false {
				typeOfVTapConfiguration.Field(i).Set(defaultValue)
			} else {
				log.Warning("vtap config no filed data", config.ID, field.Name)
			}
		}
		// 转换结构体类型
		rtapConfiguration := &models.RVTapGroupConfiguration{}
		b, err := json.Marshal(tapConfiguration)
		if err == nil {
			err = json.Unmarshal(b, rtapConfiguration)
			if err != nil {
				log.Error(err)
			}
		} else {
			log.Error(err)
		}

		vTapConfig := NewVTapConfig(rtapConfiguration)

		if config.VTapGroupLcuuid != nil {
			vtapGroupLcuuidToConfiguration[vTapConfig.VTapGroupLcuuid] = vTapConfig
		} else {
			log.Debugf("%+v", vTapConfig)
			v.realDefaultConfig = vTapConfig
		}
	}
	v.vtapGroupLcuuidToConfiguration = vtapGroupLcuuidToConfiguration
}

func (v *VTapInfo) GetDefaultMaxEscapeSeconds() int {
	defaultMaxEscapeSeconds := DEFAULT_MAX_ESCAPE_SECONDS
	if v.realDefaultConfig != nil {
		defaultMaxEscapeSeconds = v.realDefaultConfig.MaxEscapeSeconds
	}
	return defaultMaxEscapeSeconds
}

func (v *VTapInfo) GetDefaultMaxMemory() int {
	defaultMaxMemory := DEFAULT_MAX_MEMORY
	if v.realDefaultConfig != nil {
		defaultMaxMemory = v.realDefaultConfig.MaxMemory
	}

	return defaultMaxMemory
}

func (v *VTapInfo) GetVTapCacheIsReady() bool {
	return v.isReady.IsSet()
}

func (v *VTapInfo) GetTapTypes() []*trident.TapType {
	return v.metaData.GetTapTypes()
}

func (v *VTapInfo) GetConfigTSDBIP() string {
	return v.config.TsdbIP
}

func (v *VTapInfo) GetSelfUpdateUrl() string {
	return v.config.SelfUpdateUrl
}

func (v *VTapInfo) GetTridentTypeForUnkonwVTap() uint16 {
	return v.config.TridentTypeForUnkonwVtap
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
	if v.vtaps != nil {
		for _, vTap := range v.vtaps {
			key := GetKey(vTap)
			dbKeyToVTap[key] = vTap
			dbKeys.Add(key)
		}
	}
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
		}
		vTapIPs = append(vTapIPs, data)
	}
	log.Debug(vTapIPs)
	v.updateVTapIPs(vTapIPs)
}

func (v *VTapInfo) GenerateVTapCache() {
	v.loadBaseData()
	v.updateVTapInfo()
	v.updateCacheToDB()
	v.generateVTapIP()
}

func (v *VTapInfo) UpdateTSDBVTapInfo(cVTaps []*trident.CommunicationVtap, tsdbIP string) {
	log.Debugf("tsdbIP: %s, vtaps: %s", tsdbIP, cVTaps)
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
	log.Debug(v.vTapPlatformData)
}

func (v *VTapInfo) InitData() {
	v.loadBaseData()
	if v.vtaps != nil {
		for _, vtap := range v.vtaps {
			v.AddVTapCache(vtap)
		}
	} else {
		log.Error("get vtap failed or no vtap data")
	}
	log.Info("init generate all vtap platform data")
	// 最后生成romote segment
	v.generateAllVTapRemoteSegements()
	v.generateVTapIP()
	v.isReady.Set()
}

func (v *VTapInfo) generatePlatformDataAndSegment() {
	log.Info("platform data changed generate all vtap platform data")
	v.generateAllVTapPlatformData()
	log.Info("platform data changed generate all vtap segment")
	v.generateAllVTapSegements()
	pushmanager.Broadcast()
}

func (v *VTapInfo) monitorDataChanged() {
	log.Info("start monitor Data changed")
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
				log.Info("vtap config changed generate all vtap platform data ")
				v.generateAllVTapPlatformData()
				select {
				case <-v.chVTapChangedForSegment:
					log.Info("vtap changed generate all vtap remote segment")
					v.generateAllVTapRemoteSegements()
				default:
				}
			}
		case <-v.chVTapChangedForSegment:
			select {
			case <-chDataChanged:
				v.generatePlatformDataAndSegment()
			default:
				log.Info("vtap changed generate all vtap remote segment")
				v.generateAllVTapRemoteSegements()
				select {
				case <-v.chVTapChangedForPD:
					log.Info("vtap config changed generate all vtap platform data ")
					v.generateAllVTapPlatformData()
				default:
				}
			}
		}
	}

	log.Info("exit monitor data changed")
}

func (v *VTapInfo) getVTapPodDomains(c *VTapCache) []string {
	result := []string{}
	noPodDomains := []int{VTAP_TYPE_WORKLOAD_V, VTAP_TYPE_WORKLOAD_P}
	serverPodDomains := []int{VTAP_TYPE_EXSI, VTAP_TYPE_KVM, VTAP_TYPE_HYPER_V, VTAP_TYPE_HYPER_V_NETWORK}
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
			log.Errorf("vtap(%s) not found launch_server pod_node(%s)", c.GetCtrlIP(), c.GetCtrlMac())
			return result
		}
		if podNode.SubDomain == "" || podNode.Domain == podNode.SubDomain {
			podDomains.Add(podNode.Domain)
		} else {
			podDomains.Add(podNode.SubDomain)
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

func (v *VTapInfo) GetKubernetesClusterID(clusterID string, value string) string {
	return v.kcData.getClusterID(clusterID, value)
}

func (v *VTapInfo) putChVTapChangedForPD() {
	select {
	case v.chVTapChangedForPD <- struct{}{}:
	default:
	}
}

func (v *VTapInfo) updateCacheToDB() {
	log.Info("update vtap cache to db")
	hostName, err := os.Hostname()
	if err != nil {
		log.Errorf("get hostname failed. %s", err)
		return
	}

	controllerMgr := dbmgr.DBMgr[models.Controller](v.db)
	options := controllerMgr.WithName(hostName)
	controller, err := controllerMgr.GetByOption(options)
	if err != nil {
		log.Errorf("no controller(%s) in DB", hostName)
		return
	}
	config := v.config
	if len(config.MasterControllerNetIPs) == 0 {
		log.Error("no master controller ip")
		return
	}
	var ip net.IP
	if ip, err = Lookup(config.MasterControllerNetIPs[0]); err != nil {
		log.Error(err)
		return
	}
	hostIP := ip.String()
	updateVTaps := []*models.VTap{}
	keytoDBVTap := make(map[string]*models.VTap)
	vtapLcuuidToConfigFile := make(map[string]*models.VTapConfigFile)

	configFiles, err := dbmgr.DBMgr[models.VTapConfigFile](v.db).Gets()
	createConfigFiles := []*models.VTapConfigFile{}
	changeConfigFiles := []*models.VTapConfigFile{}
	for _, configFile := range configFiles {
		vtapLcuuidToConfigFile[configFile.VTapLcuuid] = configFile
	}

	dbVTaps, err := dbmgr.DBMgr[models.VTap](v.db).Gets()
	if err != nil {
		log.Error("get db vtap failed, ", err)
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
			dbVTap.CtrlMac = cacheVTap.GetCtrlMac()
			cacheExceptions := cacheVTap.GetExceptions()
			tridentExceptions := uint64(VTAP_TRIDENT_EXCEPTIONS_MASK) & uint64(cacheExceptions)
			controllerException := uint64(VTAP_CONTROLLER_EXCEPTIONS_MASK) & uint64(dbVTap.Exceptions)
			dbVTap.Exceptions = int64(controllerException | tridentExceptions)
			cacheVTap.UpdateCurControllerIP(hostIP)
			dbVTap.CurControllerIP = cacheVTap.GetCurControllerIP()
			filterFlag = true
			CacheConfigFile := cacheVTap.configFile.GetFile()
			CacheConfigFileRevision := cacheVTap.configFile.GetRevision()
			if len(CacheConfigFile) != 0 {
				dbConfigFile, ok := vtapLcuuidToConfigFile[cacheVTap.GetLcuuid()]
				if ok == false {
					vtapConfigFile := &models.VTapConfigFile{}
					vtapConfigFile.ConfigFile = CacheConfigFile
					vtapConfigFile.ConfigRevision = CacheConfigFileRevision
					vtapConfigFile.VTapLcuuid = dbVTap.Lcuuid
					createConfigFiles = append(createConfigFiles, vtapConfigFile)
				} else if dbConfigFile.ConfigFile == "" {
					dbConfigFile.ConfigFile = CacheConfigFile
					dbConfigFile.ConfigRevision = CacheConfigFileRevision
					changeConfigFiles = append(changeConfigFiles, dbConfigFile)
				} else if Find[int](LOCAL_FILE_VTAP, dbVTap.Type) && CacheConfigFileRevision != dbConfigFile.ConfigRevision {
					dbConfigFile.ConfigFile = CacheConfigFile
					dbConfigFile.ConfigRevision = CacheConfigFileRevision
					changeConfigFiles = append(changeConfigFiles, dbConfigFile)
				}
			}
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
			if now.Sub(cacheVTap.GetCachedAt()).Seconds() < 60*2 {
				// 如果时间差小于同步时间间隔，则认为刚启动,
				// 或新添加vtap，不进行状态更新
			} else if now.Sub(vtapSyncedControllerAt).Seconds() > 60*8 {
				if dbVTap.State != VTAP_STATE_NOT_CONNECTED {
					dbVTap.State = VTAP_STATE_NOT_CONNECTED
					filterFlag = true
					log.Infof("set vTap (%s) on (%s) to not connected", dbVTap.Name, dbVTap.LaunchServer)
				}
			} else if dbVTap.State == VTAP_STATE_NOT_CONNECTED {
				dbVTap.State = VTAP_STATE_NORMAL
				filterFlag = true
				log.Infof("set vTap (%s) on (%s) to normal", dbVTap.Name, dbVTap.LaunchServer)
			}
		}

		if filterFlag == true {
			updateVTaps = append(updateVTaps, dbVTap)
		}
	}
	vTapmgr := dbmgr.DBMgr[models.VTap](v.db)
	if len(updateVTaps) > 0 {
		log.Infof("update vtap count(%d)", len(updateVTaps))
		err = vTapmgr.UpdateBulk(updateVTaps)
		if err != nil {
			log.Error(err)
		}
	}
	configMgr := dbmgr.DBMgr[models.VTapConfigFile](v.db)
	if len(changeConfigFiles) > 0 {
		log.Infof("update vtap config file count(%d)", len(changeConfigFiles))
		err = configMgr.UpdateBulk(changeConfigFiles)
		if err != nil {
			log.Error(err)
		}
	}
	if len(createConfigFiles) > 0 {
		log.Infof("create vtap config file count(%d)", len(createConfigFiles))
		err = configMgr.InsertBulk(createConfigFiles)
		if err != nil {
			log.Error(err)
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

func (v *VTapInfo) getDefaultVTapGroup() string {
	if v.defaultVTapGroup != nil {
		return *v.defaultVTapGroup
	}

	return ""
}

func (v *VTapInfo) getVTapAutoRegister() bool {
	return v.config.VTapAutoRegister
}

func (v *VTapInfo) Register(tapMode int, ctrlIP string, ctrlMac string, hostIPs []string, host string, vTapGroupID string) {
	vTapRegister := newVTapRegister(tapMode, ctrlIP, ctrlMac, hostIPs, host, vTapGroupID)
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
		return
	}
	if v.getDefaultVTapGroup() == "" {
		if v.loadDefaultVTapGroup() == "" {
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
		go r.registerVTap(v, wg.Done)
	}
	wg.Wait()
}

func (v *VTapInfo) monitorVTapRegister() {
	for {
		select {
		case <-v.chVTapRegister:
			log.Info("start vtap register")
			v.StartRegister()
			select {
			case <-v.chRegisterSuccess:
				v.putChVTapChangedForSegment()
			default:
			}
			log.Info("end vtap register")
		}
	}
}

func (v *VTapInfo) TimedRefreshVTapCache() {
	v.InitData()
	go v.monitorDataChanged()
	go v.monitorVTapRegister()
	interval := time.Duration(v.config.VTapCacheRefreshInterval)
	tickerVTapCache := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-tickerVTapCache:
			log.Info("start generate vtap cache data from timed")
			v.GenerateVTapCache()
			log.Info("end generate vtap cache data from timed")
		case <-v.chVTapCacheRefresh:
			log.Info("start generate vtap cache data from rpc")
			v.GenerateVTapCache()
			pushmanager.Broadcast()
			log.Info("end generate vtap cache data from rpc")
		}
	}
}
