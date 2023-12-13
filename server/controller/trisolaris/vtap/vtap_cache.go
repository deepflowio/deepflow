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

package vtap

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	cmodel "github.com/deepflowio/deepflow/server/controller/model"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
)

type VTapConfig struct {
	models.RVTapGroupConfiguration
	ConvertedL4LogTapTypes       []uint32
	ConvertedL4LogIgnoreTapSides []uint32
	ConvertedL7LogIgnoreTapSides []uint32
	ConvertedL7LogStoreTapTypes  []uint32
	ConvertedDecapType           []uint32
	ConvertedDomains             []string
	ConvertedWasmPlugins         []string
	ConvertedSoPlugins           []string
	PluginNewUpdateTime          uint32
}

func (f *VTapConfig) convertData() {
	var err error
	f.ConvertedL4LogTapTypes, err = ConvertStrToU32List(f.L4LogTapTypes)
	if err != nil {
		log.Error(err)
	}
	f.ConvertedL4LogIgnoreTapSides, err = ConvertStrToU32List(f.L4LogIgnoreTapSides)
	if err != nil {
		log.Error(err)
	}
	f.ConvertedL7LogIgnoreTapSides, err = ConvertStrToU32List(f.L7LogIgnoreTapSides)
	if err != nil {
		log.Error(err)
	}
	f.ConvertedL7LogStoreTapTypes, err = ConvertStrToU32List(f.L7LogStoreTapTypes)
	if err != nil {
		log.Error(err)
	}
	f.ConvertedDecapType, err = ConvertStrToU32List(f.DecapType)
	if err != nil {
		log.Error(err)
	}
	if len(f.Domains) != 0 {
		f.ConvertedDomains = strings.Split(f.Domains, ",")
	}
	sort.Strings(f.ConvertedDomains)

	if len(f.WasmPlugins) != 0 {
		f.ConvertedWasmPlugins = strings.Split(f.WasmPlugins, ",")
	}
	if len(f.SoPlugins) != 0 {
		f.ConvertedSoPlugins = strings.Split(f.SoPlugins, ",")
	}

	if f.HTTPLogProxyClient == SHUT_DOWN_STR {
		f.HTTPLogProxyClient = ""
	}
	if f.HTTPLogTraceID == SHUT_DOWN_STR {
		f.HTTPLogTraceID = ""
	}
	if f.HTTPLogSpanID == SHUT_DOWN_STR {
		f.HTTPLogSpanID = ""
	}
	if f.HTTPLogXRequestID == SHUT_DOWN_STR {
		f.HTTPLogXRequestID = ""
	}
	if Find[uint32](f.ConvertedL4LogTapTypes, SHUT_DOWN_UINT) {
		f.ConvertedL4LogTapTypes = []uint32{}
	}
	if Find[uint32](f.ConvertedL7LogStoreTapTypes, SHUT_DOWN_UINT) {
		f.ConvertedL7LogStoreTapTypes = []uint32{}
	}
}

func (f *VTapConfig) modifyConfig(v *VTapInfo) {
	for _, plugin := range f.ConvertedWasmPlugins {
		if updateTime, ok := v.pluginNameToUpdateTime[plugin]; ok {
			if f.PluginNewUpdateTime < updateTime {
				f.PluginNewUpdateTime = updateTime
			}
		}
	}

	for _, plugin := range f.ConvertedSoPlugins {
		if updateTime, ok := v.pluginNameToUpdateTime[plugin]; ok {
			if f.PluginNewUpdateTime < updateTime {
				f.PluginNewUpdateTime = updateTime
			}
		}
	}
}

func NewVTapConfig(config *models.RVTapGroupConfiguration) *VTapConfig {
	vTapConfig := &VTapConfig{}
	vTapConfig.RVTapGroupConfiguration = *config
	vTapConfig.convertData()
	return vTapConfig
}

type VTapCache struct {
	id                 int
	name               *string
	state              int
	enable             int
	vTapType           int
	ctrlIP             *string
	ctrlMac            *string
	tapMac             *string
	tsdbIP             *string
	curTSDBIP          *string
	controllerIP       *string
	curControllerIP    *string
	launchServer       *string
	launchServerID     int
	az                 *string
	revision           *string
	syncedControllerAt *time.Time
	syncedTSDBAt       *time.Time
	bootTime           int
	exceptions         int64
	vTapLcuuid         *string
	vTapGroupLcuuid    *string
	cpuNum             int
	memorySize         int64
	arch               *string
	os                 *string
	kernelVersion      *string
	processName        *string
	licenseType        int
	tapMode            int
	lcuuid             *string
	licenseFunctions   *string
	licenseFunctionSet mapset.Set
	//above db Data

	enabledTrafficDistribution   atomicbool.Bool
	enabledNetworkMonitoring     atomicbool.Bool
	enabledCallMonitoring        atomicbool.Bool
	enabledFunctionMonitoring    atomicbool.Bool
	enabledApplicationMonitoring atomicbool.Bool
	enabledIndicatorMonitoring   atomicbool.Bool

	cachedAt         time.Time
	expectedRevision *string
	upgradePackage   *string
	region           *string
	regionID         int
	domain           *string

	// vtap group config
	config *atomic.Value //*VTapConfig
	// Container cluster domain where the vtap is located
	podDomains []string

	// segments
	localSegments  []*trident.Segment
	remoteSegments []*trident.Segment

	// vtap version
	pushVersionPlatformData uint64
	pushVersionPolicy       uint64
	pushVersionGroups       uint64

	controllerSyncFlag atomicbool.Bool // bool
	tsdbSyncFlag       atomicbool.Bool // bool
	// ID of the container cluster where the container type vtap resides
	podClusterID int
	// vtap vtap id
	VPCID int
	// vtap platform data
	PlatformData *atomic.Value //*PlatformData
}

func NewVTapCache(vtap *models.VTap) *VTapCache {
	vTapCache := &VTapCache{}
	vTapCache.id = vtap.ID
	vTapCache.name = proto.String(vtap.Name)
	vTapCache.state = vtap.State
	vTapCache.enable = vtap.Enable
	vTapCache.vTapType = vtap.Type
	vTapCache.ctrlIP = proto.String(vtap.CtrlIP)
	vTapCache.ctrlMac = proto.String(vtap.CtrlMac)
	vTapCache.tapMac = proto.String(vtap.TapMac)
	vTapCache.tsdbIP = proto.String(vtap.AnalyzerIP)
	vTapCache.curTSDBIP = proto.String(vtap.CurAnalyzerIP)
	vTapCache.controllerIP = proto.String(vtap.ControllerIP)
	vTapCache.curControllerIP = proto.String(vtap.CurControllerIP)
	vTapCache.launchServer = proto.String(vtap.LaunchServer)
	vTapCache.launchServerID = vtap.LaunchServerID
	vTapCache.az = proto.String(vtap.AZ)
	vTapCache.region = proto.String(vtap.Region)
	vTapCache.revision = proto.String(vtap.Revision)
	syncedControllerAt := vtap.SyncedControllerAt
	vTapCache.syncedControllerAt = &syncedControllerAt
	syncedTSDBAt := vtap.SyncedAnalyzerAt
	vTapCache.syncedTSDBAt = &syncedTSDBAt
	vTapCache.bootTime = vtap.BootTime
	vTapCache.exceptions = vtap.Exceptions
	vTapCache.vTapLcuuid = proto.String(vtap.VTapLcuuid)
	vTapCache.vTapGroupLcuuid = proto.String(vtap.VtapGroupLcuuid)
	vTapCache.cpuNum = vtap.CPUNum
	vTapCache.memorySize = vtap.MemorySize
	vTapCache.arch = proto.String(vtap.Arch)
	vTapCache.os = proto.String(vtap.Os)
	vTapCache.kernelVersion = proto.String(vtap.KernelVersion)
	vTapCache.processName = proto.String(vtap.ProcessName)
	vTapCache.licenseType = vtap.LicenseType
	vTapCache.tapMode = vtap.TapMode
	vTapCache.lcuuid = proto.String(vtap.Lcuuid)
	vTapCache.licenseFunctions = proto.String(vtap.LicenseFunctions)
	vTapCache.licenseFunctionSet = mapset.NewSet()
	vTapCache.enabledTrafficDistribution = atomicbool.NewBool(false)
	vTapCache.enabledNetworkMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledCallMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledFunctionMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledApplicationMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledIndicatorMonitoring = atomicbool.NewBool(false)

	vTapCache.cachedAt = time.Now()
	vTapCache.config = &atomic.Value{}
	vTapCache.podDomains = []string{}
	vTapCache.localSegments = []*trident.Segment{}
	vTapCache.remoteSegments = []*trident.Segment{}
	vTapCache.pushVersionPlatformData = 0
	vTapCache.pushVersionPolicy = 0
	vTapCache.pushVersionGroups = 0
	vTapCache.controllerSyncFlag = atomicbool.NewBool(false)
	vTapCache.tsdbSyncFlag = atomicbool.NewBool(false)
	vTapCache.podClusterID = 0
	vTapCache.VPCID = 0
	vTapCache.PlatformData = &atomic.Value{}
	vTapCache.expectedRevision = proto.String(vtap.ExpectedRevision)
	vTapCache.upgradePackage = proto.String(vtap.UpgradePackage)
	vTapCache.convertLicenseFunctions()
	return vTapCache
}

func ConvertStrToIntList(convertStr string) ([]int, error) {
	if len(convertStr) == 0 {
		return []int{}, nil
	}
	splitStr := strings.Split(convertStr, ",")
	result := make([]int, len(splitStr), len(splitStr))
	for index, src := range splitStr {
		target, err := strconv.Atoi(src)
		if err != nil {
			return []int{}, err
		} else {
			result[index] = target
		}
	}

	return result, nil
}

func (c *VTapCache) unsetLicenseFunctionEnable() {
	c.enabledCallMonitoring.Unset()
	c.enabledNetworkMonitoring.Unset()
	c.enabledTrafficDistribution.Unset()
	c.enabledFunctionMonitoring.Unset()
	c.enabledApplicationMonitoring.Unset()
	c.enabledIndicatorMonitoring.Unset()
}

func (c *VTapCache) convertLicenseFunctions() {
	c.unsetLicenseFunctionEnable()
	if c.licenseFunctions == nil || *c.licenseFunctions == "" {
		c.licenseFunctionSet = mapset.NewSet()
		log.Warningf("vtap(%s) no license functions", c.GetKey())
		return
	}
	licenseFunctionsInt, err := ConvertStrToIntList(*c.licenseFunctions)
	if err != nil {
		log.Errorf("convert licence functions failed err :%s", err)
		return
	}

	functionSet := mapset.NewSet()
	for _, function := range licenseFunctionsInt {
		functionSet.Add(function)
	}
	c.licenseFunctionSet = functionSet

	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_CALL_MONITORING) {
		c.enabledCallMonitoring.Set()
	}
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_NETWORK_MONITORING) {
		c.enabledNetworkMonitoring.Set()
	}
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION) {
		c.enabledTrafficDistribution.Set()
	}
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_FUNCTION_MONITORING) {
		c.enabledFunctionMonitoring.Set()
	}
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING) {
		c.enabledApplicationMonitoring.Set()
	}
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_INDICATOR_MONITORING) {
		c.enabledIndicatorMonitoring.Set()
	}
}

func (c *VTapCache) GetLocalConfig() string {
	configure := c.GetVTapConfig()
	if configure == nil {
		return ""
	}

	return configure.YamlConfig
}

var NetWorkL7ProtocolEnabled = []string{"HTTP", "DNS"}

func (c *VTapCache) modifyVTapConfigByLicense(configure *VTapConfig) {
	if configure == nil {
		return
	}
	if c.EnabledCallMonitoring() == false &&
		c.EnabledNetworkMonitoring() == false {
		configure.L7MetricsEnabled = DISABLED
		configure.ConvertedL7LogStoreTapTypes = nil
	}

	if c.EnabledNetworkMonitoring() == false {
		configure.L4PerformanceEnabled = DISABLED
		configure.ConvertedL4LogTapTypes = nil
	}

	// modify static config
	yamlConfig := &cmodel.StaticConfig{}
	err := yaml.Unmarshal([]byte(configure.YamlConfig), yamlConfig)
	if err != nil {
		log.Error(err)
		return
	}

	if c.EnabledNetworkMonitoring() == true &&
		c.EnabledCallMonitoring() == false {
		yamlConfig.L7ProtocolEnabled = NetWorkL7ProtocolEnabled
	} else if c.EnabledNetworkMonitoring() == false &&
		c.EnabledCallMonitoring() == false {
		yamlConfig.L7ProtocolEnabled = nil
	}

	if c.EnabledCallMonitoring() == false {
		if yamlConfig.Ebpf == nil {
			yamlConfig.Ebpf = &cmodel.EbpfConfig{
				Disabled: proto.Bool(true),
			}
		} else {
			yamlConfig.Ebpf.Disabled = proto.Bool(true)
		}
	}

	if c.EnabledFunctionMonitoring() == false {
		if yamlConfig.Ebpf == nil {
			yamlConfig.Ebpf = &cmodel.EbpfConfig{}
		}
		if yamlConfig.Ebpf.OnCpuProfile == nil {
			yamlConfig.Ebpf.OnCpuProfile = &cmodel.OnCpuProfile{
				Disabled: proto.Bool(true),
			}
		} else {
			yamlConfig.Ebpf.OnCpuProfile.Disabled = proto.Bool(true)
		}

		yamlConfig.ExternalProfileIntegrationDisabled = proto.Bool(true)
	}

	if c.EnabledApplicationMonitoring() == false {
		yamlConfig.ExternalTraceIntegrationDisabled = proto.Bool(true)
	}

	if c.EnabledIndicatorMonitoring() == false {
		yamlConfig.ExternalMetricIntegrationDisabled = proto.Bool(true)
	}

	b, err := yaml.Marshal(yamlConfig)
	if err != nil {
		log.Error(err)
		return
	}
	configure.YamlConfig = string(b)
}

func (c *VTapCache) EnabledCallMonitoring() bool {
	return c.enabledCallMonitoring.IsSet()
}

func (c *VTapCache) EnabledNetworkMonitoring() bool {
	return c.enabledNetworkMonitoring.IsSet()
}

func (c *VTapCache) EnabledTrafficDistribution() bool {
	return c.enabledTrafficDistribution.IsSet()
}

func (c *VTapCache) EnabledFunctionMonitoring() bool {
	return c.enabledFunctionMonitoring.IsSet()
}

func (c *VTapCache) EnabledApplicationMonitoring() bool {
	return c.enabledApplicationMonitoring.IsSet()
}

func (c *VTapCache) EnabledIndicatorMonitoring() bool {
	return c.enabledIndicatorMonitoring.IsSet()
}

func (c *VTapCache) updateLicenseFunctions(licenseFunctions string) {
	c.licenseFunctions = proto.String(licenseFunctions)
	c.convertLicenseFunctions()
}

func (c *VTapCache) GetCachedAt() time.Time {
	return c.cachedAt
}

func (c *VTapCache) UpdatePushVersionPlatformData(version uint64) {
	c.pushVersionPlatformData = version
}

func (c *VTapCache) GetPushVersionPlatformData() uint64 {
	return c.pushVersionPlatformData
}

func (c *VTapCache) UpdatePushVersionPolicy(version uint64) {
	c.pushVersionPolicy = version
}

func (c *VTapCache) GetPushVersionPolicy() uint64 {
	return c.pushVersionPolicy
}

func (c *VTapCache) UpdatePushVersionGroups(version uint64) {
	c.pushVersionGroups = version
}

func (c *VTapCache) GetPushVersionGroups() uint64 {
	return c.pushVersionGroups
}

func (c *VTapCache) GetSimplePlatformDataVersion() uint64 {
	platformData := c.GetVTapPlatformData()
	if platformData == nil {
		return 0
	}
	return platformData.GetVersion()
}

func (c *VTapCache) GetSimplePlatformDataStr() []byte {
	platformData := c.GetVTapPlatformData()
	if platformData == nil {
		return nil
	}
	return platformData.GetPlatformDataStr()
}

func (c *VTapCache) GetVTapID() uint32 {
	return uint32(c.id)
}

func (c *VTapCache) updateVTapID(vtapID int) {
	c.id = vtapID
}

func (c *VTapCache) GetFunctions() mapset.Set {
	return c.licenseFunctionSet
}

func (c *VTapCache) GetVTapType() int {
	return c.vTapType
}

func (c *VTapCache) GetVTapEnabled() int {
	return c.enable
}

func (c *VTapCache) GetVTapHost() string {
	if c.name != nil {
		return *c.name
	}
	return ""
}

func (c *VTapCache) GetConfigSyncInterval() int {
	config := c.GetVTapConfig()
	if config == nil {
		return DefaultSyncInterval
	}

	return config.SyncInterval
}

func (c *VTapCache) updateVTapHost(host string) {
	c.name = &host
}

func (c *VTapCache) GetLcuuid() string {
	if c.lcuuid != nil {
		return *c.lcuuid
	}
	return ""
}

func (c *VTapCache) GetVTapGroupLcuuid() string {
	if c.vTapGroupLcuuid != nil {
		return *c.vTapGroupLcuuid
	}
	return ""
}

func (c *VTapCache) updateVTapGroupLcuuid(lcuuid string) {
	c.vTapGroupLcuuid = &lcuuid
}

func (c *VTapCache) getPodDomains() []string {
	return c.podDomains
}

func (c *VTapCache) GetPodClusterID() int {
	return c.podClusterID
}

func (c *VTapCache) GetVPCID() int {
	return c.VPCID
}

func (c *VTapCache) updatePodDomains(podDomains []string) {
	c.podDomains = podDomains
}

func (c *VTapCache) GetKey() string {
	if c.GetCtrlMac() == "" {
		return c.GetCtrlIP()
	}
	return c.GetCtrlIP() + "-" + c.GetCtrlMac()
}

func (c *VTapCache) GetCtrlIP() string {
	if c.ctrlIP != nil {
		return *c.ctrlIP
	}
	return ""
}

func (c *VTapCache) GetCtrlMac() string {
	if c.ctrlMac != nil {
		return *c.ctrlMac
	}
	return ""
}

func (c *VTapCache) updateCtrlMac(ctrlMac string) {
	c.ctrlMac = &ctrlMac
}

func (c *VTapCache) GetAZ() string {
	if c.az != nil {
		return *c.az
	}

	return ""
}

func (c *VTapCache) updateAZ(az string) {
	c.az = &az
}

func (c *VTapCache) GetLaunchServer() string {
	if c.launchServer != nil {
		return *c.launchServer
	}

	return ""
}

var regV = regexp.MustCompile("B_LC_RELEASE_v6_[12]")

func (c *VTapCache) GetExternalAgentHTTPProxyEnabledConfig(v *VTapInfo) int {
	if enabled, ok := v.vtapGroupLcuuidToEAHPEnabled[c.GetVTapGroupLcuuid()]; ok {
		if enabled != nil {
			return *enabled
		}
	}
	if regV.MatchString(c.GetRevision()) {
		return 0
	}

	config := c.GetVTapConfig()
	if config == nil {
		return 0
	}

	return config.ExternalAgentHTTPProxyEnabled
}

func (c *VTapCache) UpdateLaunchServer(launcherServer string) {
	c.launchServer = &launcherServer
}

func (c *VTapCache) GetLaunchServerID() int {
	return c.launchServerID
}

func (c *VTapCache) UpdateLaunchServerID(id int) {
	c.launchServerID = id
}

func (c *VTapCache) SetControllerSyncFlag() {
	c.controllerSyncFlag.Set()
}

func (c *VTapCache) ResetControllerSyncFlag() {
	c.controllerSyncFlag.Unset()
}

func (c *VTapCache) SetTSDBSyncFlag() {
	c.tsdbSyncFlag.Set()
}

func (c *VTapCache) ResetTSDBSyncFlag() {
	c.tsdbSyncFlag.Unset()
}

func (c *VTapCache) GetSyncedControllerAt() *time.Time {
	return c.syncedControllerAt
}

func (c *VTapCache) UpdateSyncedControllerAt(syncTime time.Time) {
	c.syncedControllerAt = &syncTime
}

func (c *VTapCache) UpdateCurControllerIP(IP string) {
	c.curControllerIP = &IP
}

func (c *VTapCache) GetCurControllerIP() string {
	if c.curControllerIP != nil {
		return *c.curControllerIP
	}
	return ""
}

func (c *VTapCache) UpdateCurTSDBIP(IP string) {
	c.curTSDBIP = &IP
}

func (c *VTapCache) GetCurTSDBIP() string {
	if c.curTSDBIP != nil {
		return *c.curTSDBIP
	}
	return ""
}

func (c *VTapCache) UpdateSyncedTSDBAt(syncTime time.Time) {
	c.syncedTSDBAt = &syncTime
}

func (c *VTapCache) GetSyncedTSDBAt() *time.Time {
	return c.syncedTSDBAt
}

func (c *VTapCache) UpdateSyncedTSDB(syncTime time.Time, IP string) bool {
	if c.GetSyncedTSDBAt() == nil || syncTime.After(*c.GetSyncedTSDBAt()) {
		c.UpdateSyncedTSDBAt(syncTime)
		c.UpdateCurTSDBIP(IP)
		return true
	}

	return false
}

func (c *VTapCache) UpdateBootTime(bootTime uint32) {
	c.bootTime = int(bootTime)
}

func (c *VTapCache) GetBootTime() int {
	return c.bootTime
}

func (c *VTapCache) GetCPUNum() int {
	return c.cpuNum
}

func (c *VTapCache) updateCPUNum(cpuNum int) {
	c.cpuNum = cpuNum
}

func (c *VTapCache) GetMemorySize() int64 {
	return c.memorySize
}

func (c *VTapCache) updateMemorySize(memorySize int64) {
	c.memorySize = memorySize
}

func (c *VTapCache) GetArch() string {
	if c.arch != nil {
		return *c.arch
	}
	return ""
}

func (c *VTapCache) updateArch(arch string) {
	c.arch = &arch
}

func (c *VTapCache) GetOs() string {
	if c.os != nil {
		return *c.os
	}
	return ""
}

func (c *VTapCache) updateOs(os string) {
	c.os = &os
}

func (c *VTapCache) GetKernelVersion() string {
	if c.kernelVersion != nil {
		return *c.kernelVersion
	}
	return ""
}

func (c *VTapCache) updateKernelVersion(version string) {
	c.kernelVersion = &version
}

func (c *VTapCache) GetProcessName() string {
	if c.processName != nil {
		return *c.processName
	}
	return ""
}

func (c *VTapCache) updateProcessName(processName string) {
	c.processName = &processName
}

func (c *VTapCache) GetTapMode() int {
	return c.tapMode
}

func (c *VTapCache) updateTapMode(tapMode int) {
	c.tapMode = tapMode
}

func (c *VTapCache) UpdateRevision(revision string) {
	c.revision = &revision
}

func (c *VTapCache) GetRevision() string {
	if c.revision != nil {
		return *c.revision
	}

	return ""
}

func (c *VTapCache) GetRegion() string {
	if c.region != nil {
		return *c.region
	}

	return ""
}

func (c *VTapCache) updateRegion(region string) {
	c.region = &region
}

func (c *VTapCache) GetRegionID() int {
	return c.regionID
}

func (c *VTapCache) UpdateUpgradeInfo(expectedRevision string, upgradePackage string) {
	c.expectedRevision = &expectedRevision
	c.upgradePackage = &upgradePackage
}

func (c *VTapCache) GetExpectedRevision() string {
	if c.expectedRevision != nil {
		return *c.expectedRevision
	}
	return ""
}

func (c *VTapCache) GetUpgradePackage() string {
	if c.upgradePackage != nil {
		return *c.upgradePackage
	}

	return ""
}

func (c *VTapCache) GetExceptions() int64 {
	return atomic.LoadInt64(&c.exceptions)
}

// 只更新采集器返回的异常，控制器异常不用更新，由控制器处理其异常
func (c *VTapCache) UpdateExceptions(exceptions int64) {
	log.Infof(
		"modify vtap(%s) exception %d to %d",
		c.GetVTapHost(), c.GetExceptions(), exceptions)
	atomic.StoreInt64(&c.exceptions, int64(exceptions))
}

func (c *VTapCache) UpdateSystemInfoFromGrpc(cpuNum int, memorySize int64, arch, os, kernelVersion, processName string) {
	if cpuNum != 0 {
		c.updateCPUNum(cpuNum)
	}
	if memorySize != 0 {
		c.updateMemorySize(memorySize)
	}
	if arch != "" {
		c.updateArch(arch)
	}
	if os != "" {
		c.updateOs(os)
	}
	if kernelVersion != "" {
		c.updateKernelVersion(kernelVersion)
	}
	if processName != "" {
		c.updateProcessName(processName)
	}
}

func (c *VTapCache) UpdateCtrlMacFromGrpc(ctrlMac string) {
	if c.GetCtrlMac() == "" || c.GetCtrlMac() != ctrlMac {
		c.updateCtrlMac(ctrlMac)
		log.Infof("grpc modify vtap(%s) ctrl_mac (%s) to (%s)",
			c.GetVTapHost(), c.GetCtrlMac(), ctrlMac)
	}
}

func (c *VTapCache) updateCtrlMacFromDB(ctrlMac string) {
	if c.GetCtrlMac() == "" && ctrlMac != "" {
		c.updateCtrlMac(ctrlMac)
		log.Infof("db modify vtap(%s) ctrl_mac (%s) to (%s)",
			c.GetVTapHost(), c.GetCtrlMac(), ctrlMac)
	}
}

func (c *VTapCache) init(v *VTapInfo) {
	c.modifyVTapCache(v)
	c.initVTapPodDomains(v)
	c.initVTapConfig(v)
}

func (c *VTapCache) modifyVTapCache(v *VTapInfo) {
	if c.state == VTAP_STATE_PENDING {
		c.enable = 0
	}
	var ok bool
	c.regionID = v.GetRegionIDByLcuuid(c.GetRegion())
	vTapType := c.GetVTapType()
	if vTapType == VTAP_TYPE_POD_HOST || vTapType == VTAP_TYPE_POD_VM {
		c.podClusterID, ok = v.lcuuidToPodClusterID[c.GetLcuuid()]
		if ok == false {
			log.Warningf("vtap(%s) not found podClusterID", c.GetVTapHost())
		}
		c.VPCID, ok = v.lcuuidToVPCID[c.GetLcuuid()]
		if ok == false {
			log.Warningf("vtap(%s) not found VPCID", c.GetVTapHost())
		}
	} else if vTapType == VTAP_TYPE_K8S_SIDECAR {
		pod := v.metaData.GetPlatformDataOP().GetRawData().GetPod(c.GetLaunchServerID())
		if pod != nil {
			c.podClusterID = pod.PodClusterID
			c.VPCID = pod.VPCID
		}
	} else if vTapType == VTAP_TYPE_WORKLOAD_V || vTapType == VTAP_TYPE_WORKLOAD_P {
		c.VPCID, ok = v.lcuuidToVPCID[c.GetLcuuid()]
		if ok == false {
			log.Warningf("vtap(%s) not found VPCID", c.GetVTapHost())
		}
	} else if vTapType == VTAP_TYPE_HYPER_V && v.hypervNetworkHostIds.Contains(c.GetLaunchServerID()) {
		c.vTapType = VTAP_TYPE_HYPER_V_NETWORK
		c.VPCID, ok = v.hostIDToVPCID[c.GetLaunchServerID()]
		if ok == false {
			log.Warningf("vtap(%s) not found VPCID", c.GetVTapHost())
		}
	} else if vTapType == VTAP_TYPE_KVM || vTapType == VTAP_TYPE_HYPER_V {
		c.VPCID, ok = v.hostIDToVPCID[c.GetLaunchServerID()]
		if ok == false {
			log.Warningf("vtap(%s) not found VPCID", c.GetVTapHost())
		}
	}
}

func (c *VTapCache) initVTapPodDomains(v *VTapInfo) {
	c.podDomains = v.getVTapPodDomains(c)
}

func (c *VTapCache) initVTapConfig(v *VTapInfo) {
	realConfig := VTapConfig{}
	config, ok := v.vtapGroupLcuuidToConfiguration[c.GetVTapGroupLcuuid()]
	if ok {
		realConfig = *config
	} else {
		if v.realDefaultConfig != nil {
			realConfig = *v.realDefaultConfig
		}
	}
	if v.config.BillingMethod == BILLING_METHOD_LICENSE {
		c.modifyVTapConfigByLicense(&realConfig)
	}
	realConfig.modifyConfig(v)
	c.updateVTapConfig(&realConfig)
}

func (c *VTapCache) updateVTapConfigFromDB(v *VTapInfo) {
	newConfig := VTapConfig{}
	config, ok := v.vtapGroupLcuuidToConfiguration[c.GetVTapGroupLcuuid()]
	if ok {
		newConfig = *config
	} else {
		if v.realDefaultConfig != nil {
			newConfig = *v.realDefaultConfig
		}
	}
	oldConfig := c.GetVTapConfig()
	if oldConfig != nil {
		// 采集器配置发生变化 重新生成平台数据
		if newConfig.Domains != oldConfig.Domains || newConfig.PodClusterInternalIP != oldConfig.PodClusterInternalIP {
			v.setVTapChangedForPD()
		}
	}

	if v.config.BillingMethod == BILLING_METHOD_LICENSE {
		c.modifyVTapConfigByLicense(&newConfig)
	}
	newConfig.modifyConfig(v)
	c.updateVTapConfig(&newConfig)
}

func (c *VTapCache) GetConfigTapMode() int {
	config := c.GetVTapConfig()
	if config == nil {
		return -1
	}
	return config.TapMode
}

func (c *VTapCache) updateVTapCacheFromDB(vtap *models.VTap, v *VTapInfo) {
	c.updateCtrlMacFromDB(vtap.CtrlMac)
	c.state = vtap.State
	c.enable = vtap.Enable
	if v.config.BillingMethod == BILLING_METHOD_LICENSE {
		c.updateLicenseFunctions(vtap.LicenseFunctions)
	}
	c.updateTapMode(vtap.TapMode)
	if c.vTapType != vtap.Type {
		c.vTapType = vtap.Type
		v.setVTapChangedForSegment()
	}
	if c.GetVTapHost() != vtap.Name {
		c.updateVTapHost(vtap.Name)
	}
	c.updateVTapID(vtap.ID)
	if c.GetControllerIP() != vtap.ControllerIP {
		c.updateControllerIP(vtap.ControllerIP)
	}
	if c.GetTSDBIP() != vtap.AnalyzerIP {
		c.updateTSDBIP(vtap.AnalyzerIP)
	}
	if !vtap.SyncedControllerAt.IsZero() {
		if c.GetSyncedControllerAt() == nil {
			c.UpdateSyncedControllerAt(vtap.SyncedControllerAt)
		} else {
			maxTime := MaxTime(vtap.SyncedControllerAt, *c.GetSyncedControllerAt())
			c.UpdateSyncedControllerAt(maxTime)
		}
	}
	if !vtap.SyncedAnalyzerAt.IsZero() {
		if c.GetSyncedTSDBAt() == nil {
			c.UpdateSyncedTSDBAt(vtap.SyncedAnalyzerAt)
		} else {
			maxTime := MaxTime(vtap.SyncedAnalyzerAt, *c.GetSyncedTSDBAt())
			c.UpdateSyncedTSDBAt(maxTime)
		}
	}
	if c.GetLaunchServer() != vtap.LaunchServer {
		c.UpdateLaunchServer(vtap.LaunchServer)
	}
	c.UpdateLaunchServerID(vtap.LaunchServerID)
	if c.GetAZ() != vtap.AZ {
		c.updateAZ(vtap.AZ)
	}
	if c.GetRegion() != vtap.Region {
		c.updateRegion(vtap.Region)
	}
	c.modifyVTapCache(v)
	// 采集器组变化 重新生成平台数据
	if c.GetVTapGroupLcuuid() != vtap.VtapGroupLcuuid {
		c.updateVTapGroupLcuuid(vtap.VtapGroupLcuuid)
		v.setVTapChangedForPD()
	}
	c.updateVTapConfigFromDB(v)
	newPodDomains := v.getVTapPodDomains(c)
	oldPodDomains := c.getPodDomains()
	// podDomain 发生变化重新生成平台数据
	if !SliceEqual[string](newPodDomains, oldPodDomains) {
		c.updatePodDomains(newPodDomains)
		v.setVTapChangedForPD()
	}
	if c.GetConfigTapMode() != c.GetTapMode() {
		log.Warningf("config tap_mode(%d) is not equal to vtap(%s) tap_mode(%d)", c.GetConfigTapMode(), c.GetKey(), c.GetTapMode())
	}
}

func (c *VTapCache) GetControllerIP() string {
	if c.controllerIP != nil {
		return *c.controllerIP
	}
	return ""
}

func (c *VTapCache) updateControllerIP(ip string) {
	c.controllerIP = &ip
}

func (c *VTapCache) GetTSDBIP() string {
	if c.tsdbIP != nil {
		return *c.tsdbIP
	}
	return ""
}

func (c *VTapCache) updateTSDBIP(ip string) {
	c.tsdbIP = &ip
}

func (c *VTapCache) GetVTapConfig() *VTapConfig {
	config := c.config.Load()
	if config == nil {
		log.Warningf("vtap(%s) no config", c.GetVTapHost())
		return nil
	}
	return config.(*VTapConfig)
}

func (c *VTapCache) updateVTapConfig(cfg *VTapConfig) {
	if cfg == nil {
		return
	}
	c.config.Store(cfg)
}

func (c *VTapCache) setVTapPlatformData(d *metadata.PlatformData) {
	if d == nil {
		return
	}
	c.PlatformData.Store(d)
}

func (c *VTapCache) GetVTapPlatformData() *metadata.PlatformData {
	platformData := c.PlatformData.Load()
	if platformData == nil {
		log.Warningf("vtap(%s) no platformData", c.GetVTapHost())
		return nil
	}
	return platformData.(*metadata.PlatformData)
}

func (c *VTapCache) setVTapLocalSegments(segments []*trident.Segment) {
	c.localSegments = segments
}

func (c *VTapCache) GetVTapLocalSegments() []*trident.Segment {
	return c.localSegments
}

func (c *VTapCache) setVTapRemoteSegments(segments []*trident.Segment) {
	c.remoteSegments = segments
}

func (c *VTapCache) GetVTapRemoteSegments() []*trident.Segment {
	return c.remoteSegments
}

type VTapCacheMap struct {
	sync.RWMutex
	keyToVTapCache map[string]*VTapCache
}

func NewVTapCacheMap() *VTapCacheMap {
	return &VTapCacheMap{
		keyToVTapCache: make(map[string]*VTapCache),
	}
}

func (m *VTapCacheMap) Add(vTapCache *VTapCache) {
	m.Lock()
	defer m.Unlock()
	m.keyToVTapCache[vTapCache.GetKey()] = vTapCache
}

func (m *VTapCacheMap) Delete(key string) {
	m.Lock()
	defer m.Unlock()
	delete(m.keyToVTapCache, key)
}

func (m *VTapCacheMap) Get(key string) *VTapCache {
	m.RLock()
	defer m.RUnlock()
	if vTapCache, ok := m.keyToVTapCache[key]; ok {
		return vTapCache
	}

	return nil
}

func (m *VTapCacheMap) GetCount() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.keyToVTapCache)
}

func (m *VTapCacheMap) GetKeySet() mapset.Set {
	m.RLock()
	defer m.RUnlock()
	keys := mapset.NewSet()
	for key, _ := range m.keyToVTapCache {
		keys.Add(key)
	}

	return keys
}

func (m *VTapCacheMap) List() []string {
	m.RLock()
	defer m.RUnlock()
	keys := make([]string, 0, len(m.keyToVTapCache))
	for key, _ := range m.keyToVTapCache {
		keys = append(keys, key)
	}

	return keys
}

type VTapIDCacheMap struct {
	sync.RWMutex
	keyToVTapCache map[int]*VTapCache
}

func NewVTapIDCacheMap() *VTapIDCacheMap {
	return &VTapIDCacheMap{
		keyToVTapCache: make(map[int]*VTapCache),
	}
}

func (m *VTapIDCacheMap) Add(vTapCache *VTapCache) {
	m.Lock()
	defer m.Unlock()
	m.keyToVTapCache[vTapCache.id] = vTapCache
}

func (m *VTapIDCacheMap) Delete(key int) {
	m.Lock()
	defer m.Unlock()
	delete(m.keyToVTapCache, key)
}

func (m *VTapIDCacheMap) Get(key int) *VTapCache {
	m.RLock()
	defer m.RUnlock()
	if vTapCache, ok := m.keyToVTapCache[key]; ok {
		return vTapCache
	}

	return nil
}

type KvmVTapCacheMap struct {
	sync.RWMutex
	keyToVTapCache map[string]*VTapCache
}

func NewKvmVTapCacheMap() *KvmVTapCacheMap {
	return &KvmVTapCacheMap{
		keyToVTapCache: make(map[string]*VTapCache),
	}
}

func (m *KvmVTapCacheMap) Add(vTapCache *VTapCache) {
	m.Lock()
	defer m.Unlock()
	m.keyToVTapCache[vTapCache.GetCtrlIP()] = vTapCache
}

func (m *KvmVTapCacheMap) Delete(key string) {
	m.Lock()
	defer m.Unlock()
	delete(m.keyToVTapCache, key)
}

func (m *KvmVTapCacheMap) Get(key string) *VTapCache {
	m.RLock()
	defer m.RUnlock()
	if vTapCache, ok := m.keyToVTapCache[key]; ok {
		return vTapCache
	}

	return nil
}
