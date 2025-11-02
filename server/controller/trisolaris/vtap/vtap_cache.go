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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	kyaml "github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"github.com/mohae/deepcopy"
	"gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/agent_config"
	. "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata/agentmetadata"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
)

type VTapConfig struct {
	agent_config.AgentGroupConfigModel
	ConvertedL4LogTapTypes       []uint32
	ConvertedL4LogIgnoreTapSides []uint32
	ConvertedL7LogIgnoreTapSides []uint32
	ConvertedL7LogStoreTapTypes  []uint32
	ConvertedDecapType           []uint32
	ConvertedDomains             []string
	ConvertedWasmPlugins         []string
	ConvertedSoPlugins           []string
	PluginNewUpdateTime          uint32
	UserConfig                   *koanf.Koanf
}

func (f *VTapConfig) GetUserConfig() *koanf.Koanf {
	return f.UserConfig.Copy()
}

func (f *VTapConfig) convertData() {
	var err error
	if f.L4LogTapTypes != nil {
		f.ConvertedL4LogTapTypes, err = ConvertStrToU32List(*f.L4LogTapTypes)
		if err != nil {
			log.Error(err)
		}
	}
	if f.L4LogIgnoreTapSides != nil {
		f.ConvertedL4LogIgnoreTapSides, err = ConvertStrToU32List(*f.L4LogIgnoreTapSides)
		if err != nil {
			log.Error(err)
		}
	}
	if f.L7LogIgnoreTapSides != nil {
		f.ConvertedL7LogIgnoreTapSides, err = ConvertStrToU32List(*f.L7LogIgnoreTapSides)
		if err != nil {
			log.Error(err)
		}
	}
	if f.L7LogStoreTapTypes != nil {
		f.ConvertedL7LogStoreTapTypes, err = ConvertStrToU32List(*f.L7LogStoreTapTypes)
		if err != nil {
			log.Error(err)
		}
	}
	if f.DecapType != nil {
		f.ConvertedDecapType, err = ConvertStrToU32List(*f.DecapType)
		if err != nil {
			log.Error(err)
		}
	}
	if f.Domains != nil && len(*f.Domains) != 0 {
		f.ConvertedDomains = strings.Split(*f.Domains, ",")
	}
	sort.Strings(f.ConvertedDomains)

	if f.WasmPlugins != nil && len(*f.WasmPlugins) != 0 {
		f.ConvertedWasmPlugins = strings.Split(*f.WasmPlugins, ",")
	}
	if f.SoPlugins != nil && len(*f.SoPlugins) != 0 {
		f.ConvertedSoPlugins = strings.Split(*f.SoPlugins, ",")
	}

	if f.HTTPLogProxyClient != nil && *f.HTTPLogProxyClient == SHUT_DOWN_STR {
		f.HTTPLogProxyClient = proto.String("")
	}
	if f.HTTPLogTraceID != nil && *f.HTTPLogTraceID == SHUT_DOWN_STR {
		f.HTTPLogTraceID = proto.String("")
	}
	if f.HTTPLogSpanID != nil && *f.HTTPLogSpanID == SHUT_DOWN_STR {
		f.HTTPLogSpanID = proto.String("")
	}
	if f.HTTPLogXRequestID != nil && *f.HTTPLogXRequestID == SHUT_DOWN_STR {
		f.HTTPLogXRequestID = proto.String("")
	}
	if Find[uint32](f.ConvertedL4LogTapTypes, SHUT_DOWN_UINT) {
		f.ConvertedL4LogTapTypes = []uint32{}
	}
	if Find[uint32](f.ConvertedL7LogStoreTapTypes, SHUT_DOWN_UINT) {
		f.ConvertedL7LogStoreTapTypes = []uint32{}
	}
}

func (f *VTapConfig) modifyUserConfig(c *VTapCache) {
	if f.UserConfig == nil {
		log.Error("vtap configure is nil")
		return
	}
	if !f.UserConfig.Exists(CONFIG_KEY_PROXY_CONTROLLER_IP) {
		f.UserConfig.Set(CONFIG_KEY_PROXY_CONTROLLER_IP, c.GetControllerIP())
	}
	if !f.UserConfig.Exists(CONFIG_KEY_INGESTER_IP) {
		f.UserConfig.Set(CONFIG_KEY_INGESTER_IP, c.GetTSDBIP())
	}
	domainFilters := f.UserConfig.Strings(CONFIG_KEY_DOMAIN_FILTER)
	if len(domainFilters) > 0 {
		sort.Strings(domainFilters)
		f.UserConfig.Set(CONFIG_KEY_DOMAIN_FILTER, domainFilters)
	}
}

func (f *VTapConfig) getDomainFilters() []string {
	if f.UserConfig == nil {
		return nil
	}
	return f.UserConfig.Strings(CONFIG_KEY_DOMAIN_FILTER)
}

func (f *VTapConfig) getPodClusterInternalIP() bool {
	if f.UserConfig == nil {
		return true
	}

	return f.UserConfig.Bool("inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster")
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

func NewVTapConfig(config *agent_config.AgentGroupConfigModel, agentConfigYaml string) *VTapConfig {
	vTapConfig := &VTapConfig{}
	vTapConfig.AgentGroupConfigModel = *config
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider([]byte(agentConfigYaml)), kyaml.Parser()); err != nil {
		log.Error(err)
	}
	vTapConfig.UserConfig = k
	vTapConfig.convertData()
	return vTapConfig
}

type VTapCache struct {
	id                 int
	name               *string
	rawHostname        *string
	state              int
	enable             int
	vTapType           int
	owner              *string
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
	vTapGroupShortID   *string
	cpuNum             int
	memorySize         int64
	arch               *string
	os                 *string
	kernelVersion      *string
	processName        *string
	currentK8sImage    *string
	licenseType        int
	tapMode            int
	teamID             int
	organizeID         int
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
	enabledLogMonitoring         atomicbool.Bool

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

	// agent segments
	agentLocalSegments  []*agent.Segment
	agentRemoteSegments []*agent.Segment

	// vtap version
	pushVersionPlatformData uint64
	pushVersionPolicy       uint64
	pushVersionGroups       uint64

	// grpc buffer size
	grpcBufferSize    uint64
	lastSyncBytes     uint64
	lastPushBytes     uint64
	lastGPIDSyncBytes uint64

	controllerSyncFlag atomicbool.Bool // bool
	tsdbSyncFlag       atomicbool.Bool // bool
	// ID of the container cluster where the container type vtap resides
	podClusterID int
	// vtap vtap id
	VPCID int
	// vtap platform data
	PlatformData *atomic.Value //*PlatformData
	// new agent  platform data
	AgentPlatformData *atomic.Value //*agentmetadata.PlatformData

	vTapInfo *VTapInfo
}

func (c *VTapCache) String() string {
	return fmt.Sprintf(
		"{id: %d, name: %s, rawHostname: %s, state: %d, enable: %d, vTapType: %d, "+
			"ctrlIP:%s, ctrlMac:%s, tsdbIP: %s, curTSDBIP: %s, controllerIP: %s, "+
			"curControllerIP: %s, launchServer: %s, launchServerID: %d, syncedControllerAt: %s, "+
			"syncedTSDBAt: %s, bootTime: %d, exceptions: %d, vTapGroupLcuuid: %s, vTapGroupShortID: %s, licenseType: %d, "+
			"tapMode: %d, teamID: %d, organizeID: %d, licenseFunctionSet: %s, enabledTrafficDistribution: %v, "+
			"enabledNetworkMonitoring: %v, enabledCallMonitoring: %v, enabledFunctionMonitoring: %v, "+
			"enabledApplicationMonitoring: %v, enabledIndicatorMonitoring: %v, enabledLogMonitoring: %v, "+
			"podDomains: %v, pushVersionPlatformData: %d, pushVersionPolicy: %d, pushVersionGroups: %d, "+
			"expectedRevision: %s, upgradePackage: %s, podClusterID: %d, VPCID: %d, grpcBufferSize: %d}",
		c.GetVTapID(), c.GetVTapHost(), c.GetVTapRawHostname(), c.GetVTapState(), c.GetVTapEnabled(), c.GetVTapType(),
		c.GetCtrlIP(), c.GetCtrlMac(), c.GetTSDBIP(), c.GetCurTSDBIP(), c.GetControllerIP(),
		c.GetCurControllerIP(), c.GetLaunchServer(), c.GetLaunchServerID(), c.GetSyncedControllerAt(),
		c.GetSyncedTSDBAt(), c.GetBootTime(), c.GetExceptions(), c.GetVTapGroupLcuuid(), c.GetVTapGroupShortID(), c.GetLicenseType(),
		c.tapMode, c.teamID, c.organizeID, c.licenseFunctionSet, c.EnabledTrafficDistribution(),
		c.EnabledNetworkMonitoring(), c.EnabledCallMonitoring(), c.EnabledFunctionMonitoring(),
		c.EnabledApplicationMonitoring(), c.EnabledIndicatorMonitoring(), c.EnabledLogMonitoring(),
		c.podDomains, c.pushVersionPlatformData, c.pushVersionPolicy, c.pushVersionGroups,
		c.GetExpectedRevision(), c.GetUpgradePackage(), c.podClusterID, c.VPCID, c.GetGRPCBufferSize())
}

func NewVTapCache(vtap *mysqlmodel.VTap, vTapInfo *VTapInfo) *VTapCache {
	vTapCache := &VTapCache{}
	vTapCache.id = vtap.ID
	vTapCache.name = proto.String(vtap.Name)
	vTapCache.rawHostname = proto.String(vtap.RawHostname)
	vTapCache.owner = proto.String(vtap.Owner)
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
	vTapCache.vTapGroupShortID = proto.String(vTapInfo.vtapGroupLcuuidToShortID[vtap.VtapGroupLcuuid])
	vTapCache.cpuNum = vtap.CPUNum
	vTapCache.memorySize = vtap.MemorySize
	vTapCache.grpcBufferSize = vtap.GRPCBufferSize
	vTapCache.arch = proto.String(vtap.Arch)
	vTapCache.os = proto.String(vtap.Os)
	vTapCache.kernelVersion = proto.String(vtap.KernelVersion)
	vTapCache.processName = proto.String(vtap.ProcessName)
	vTapCache.currentK8sImage = proto.String(vtap.CurrentK8sImage)
	vTapCache.licenseType = vtap.LicenseType
	vTapCache.tapMode = vtap.TapMode
	vTapCache.teamID = vtap.TeamID
	vTapCache.organizeID = vTapInfo.GetORGID()
	vTapCache.lcuuid = proto.String(vtap.Lcuuid)
	vTapCache.licenseFunctions = proto.String(vtap.LicenseFunctions)
	vTapCache.licenseFunctionSet = mapset.NewSet()
	vTapCache.enabledTrafficDistribution = atomicbool.NewBool(false)
	vTapCache.enabledNetworkMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledCallMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledFunctionMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledApplicationMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledIndicatorMonitoring = atomicbool.NewBool(false)
	vTapCache.enabledLogMonitoring = atomicbool.NewBool(false)

	vTapCache.cachedAt = time.Now()
	vTapCache.config = &atomic.Value{}
	vTapCache.podDomains = []string{}
	vTapCache.localSegments = []*trident.Segment{}
	vTapCache.remoteSegments = []*trident.Segment{}

	vTapCache.agentLocalSegments = []*agent.Segment{}
	vTapCache.agentRemoteSegments = []*agent.Segment{}

	vTapCache.pushVersionPlatformData = 0
	vTapCache.pushVersionPolicy = 0
	vTapCache.pushVersionGroups = 0
	vTapCache.controllerSyncFlag = atomicbool.NewBool(false)
	vTapCache.tsdbSyncFlag = atomicbool.NewBool(false)
	vTapCache.podClusterID = 0
	vTapCache.VPCID = 0
	vTapCache.PlatformData = &atomic.Value{}
	vTapCache.AgentPlatformData = &atomic.Value{}
	vTapCache.expectedRevision = proto.String(vtap.ExpectedRevision)
	vTapCache.upgradePackage = proto.String(vtap.UpgradePackage)
	vTapCache.vTapInfo = vTapInfo
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
	c.enabledLogMonitoring.Unset()
}

func (c *VTapCache) convertLicenseFunctions() {
	v := c.vTapInfo
	c.unsetLicenseFunctionEnable()
	if c.GetVTapType() != VTAP_TYPE_DEDICATED && c.GetOwner() == VTAP_OWNER_DEEPFLOW {
		c.enabledCallMonitoring.Set()
		c.enabledNetworkMonitoring.Set()
		c.enabledTrafficDistribution.Set()
		c.enabledFunctionMonitoring.Set()
		c.enabledApplicationMonitoring.Set()
		c.enabledLogMonitoring.Set()
		c.enabledIndicatorMonitoring.Set()
		return
	}
	if c.GetVTapType() == VTAP_TYPE_DEDICATED {
		c.enabledCallMonitoring.Set()
		c.enabledLogMonitoring.Set()
		c.enabledIndicatorMonitoring.Set()
	}
	if c.licenseFunctions == nil || *c.licenseFunctions == "" {
		c.licenseFunctionSet = mapset.NewSet()
		log.Warningf(v.Logf("vtap(%s) no license functions", c.GetKey()))
		return
	}
	licenseFunctionsInt, err := ConvertStrToIntList(*c.licenseFunctions)
	if err != nil {
		log.Errorf(v.Logf("convert licence functions failed err :%s", err))
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
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_DATABASE_MONITORING) {
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
	if Find[int](licenseFunctionsInt, VTAP_LICENSE_FUNCTION_LOG_MONITORING) {
		c.enabledLogMonitoring.Set()
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
	if configure.YamlConfig == nil {
		return ""
	}

	return *configure.YamlConfig
}

var NetWorkL7ProtocolEnabled = []string{"HTTP", "DNS"}

func (c *VTapCache) modifyVTapConfigByLicense(configure *VTapConfig) {
	if configure == nil {
		log.Error("vtap configure is nil")
		return
	}
	if c.EnabledCallMonitoring() == false && c.EnabledNetworkMonitoring() == false {
		*configure.L7MetricsEnabled = DISABLED
		configure.ConvertedL7LogStoreTapTypes = nil

		if configure.UserConfig != nil {
			configure.UserConfig.Set("outputs.flow_metrics.filters.apm_metrics", false)
			configure.UserConfig.Set("outputs.flow_log.filters.l7_capture_network_types", []int{-1})
		}
	}

	if c.EnabledNetworkMonitoring() == false {
		*configure.L4PerformanceEnabled = DISABLED
		configure.ConvertedL4LogTapTypes = nil

		if configure.UserConfig != nil {
			configure.UserConfig.Set("outputs.flow_metrics.filters.npm_metrics", false)
			configure.UserConfig.Set("outputs.flow_log.filters.l4_capture_network_types", []int{-1})
		}
	}
	v := c.vTapInfo
	// modify static config
	yamlConfig := &agent_config.StaticConfig{}
	if configure.YamlConfig != nil {
		if err := yaml.Unmarshal([]byte(*configure.YamlConfig), yamlConfig); err != nil {
			log.Error(v.Logf("%s", err))
			return
		}
	}

	if c.EnabledNetworkMonitoring() == true && c.EnabledCallMonitoring() == false {
		yamlConfig.L7ProtocolEnabled = NetWorkL7ProtocolEnabled

		if configure.UserConfig != nil {
			configure.UserConfig.Set("processors.request_log.application_protocol_inference.enabled_protocols", NetWorkL7ProtocolEnabled)
		}
	} else if c.EnabledNetworkMonitoring() == false && c.EnabledCallMonitoring() == false {
		yamlConfig.L7ProtocolEnabled = nil

		if configure.UserConfig != nil {
			configure.UserConfig.Set("processors.request_log.application_protocol_inference.enabled_protocols", []string{})
		}
	}

	if c.EnabledCallMonitoring() == false {
		disabled := int(DISABLED)
		if yamlConfig.Ebpf == nil {
			yamlConfig.Ebpf = &agent_config.EbpfConfig{
				Disabled:           proto.Bool(true),
				IOEventCollectMode: &disabled,
			}
		} else {
			yamlConfig.Ebpf.Disabled = proto.Bool(true)
			yamlConfig.Ebpf.IOEventCollectMode = &disabled
		}

		if configure.UserConfig != nil {
			configure.UserConfig.Set("inputs.ebpf.disabled", true)
			configure.UserConfig.Set("inputs.ebpf.file.io_event.collect_mode", 0)
		}
	}

	if c.EnabledFunctionMonitoring() == false {
		if yamlConfig.Ebpf == nil {
			yamlConfig.Ebpf = &agent_config.EbpfConfig{}
		}
		if yamlConfig.Ebpf.OnCpuProfile == nil {
			yamlConfig.Ebpf.OnCpuProfile = &agent_config.OnCpuProfile{
				Disabled: proto.Bool(true),
			}
		} else {
			yamlConfig.Ebpf.OnCpuProfile.Disabled = proto.Bool(true)
		}
		if yamlConfig.Ebpf.OffCpuProfile == nil {
			yamlConfig.Ebpf.OffCpuProfile = &agent_config.OffCpuProfile{
				Disabled: proto.Bool(true),
			}
		} else {
			yamlConfig.Ebpf.OffCpuProfile.Disabled = proto.Bool(true)
		}

		yamlConfig.ExternalProfileIntegrationDisabled = proto.Bool(true)

		if configure.UserConfig != nil {
			configure.UserConfig.Set("inputs.ebpf.profile.on_cpu.disabled", true)
			configure.UserConfig.Set("inputs.ebpf.profile.off_cpu.disabled", true)
			configure.UserConfig.Set("inputs.integration.feature_control.profile_integration_disabled", true)
		}
	}

	if c.EnabledApplicationMonitoring() == false {
		yamlConfig.ExternalTraceIntegrationDisabled = proto.Bool(true)

		if configure.UserConfig != nil {
			configure.UserConfig.Set("inputs.integration.feature_control.trace_integration_disabled", true)
		}
	}

	if c.EnabledIndicatorMonitoring() == false {
		yamlConfig.ExternalMetricIntegrationDisabled = proto.Bool(true)

		if configure.UserConfig != nil {
			configure.UserConfig.Set("inputs.integration.feature_control.metric_integration_disabled", true)
		}
	}
	if c.EnabledLogMonitoring() == false {
		yamlConfig.ExternalLogIntegrationDisabled = proto.Bool(true)

		if configure.UserConfig != nil {
			configure.UserConfig.Set("inputs.integration.feature_control.log_integration_disabled", true)
		}
	}

	b, err := yaml.Marshal(yamlConfig)
	if err != nil {
		log.Error(err)
		return
	}
	configure.YamlConfig = proto.String(string(b))
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

func (c *VTapCache) EnabledLogMonitoring() bool {
	return c.enabledLogMonitoring.IsSet()
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

func (c *VTapCache) GetAgentPlatformDataVersion() uint64 {
	platformData := c.GetAgentPlatformData()
	if platformData == nil {
		return 0
	}
	return platformData.GetVersion()
}

func (c *VTapCache) GetAgentPlatformDataStr() []byte {
	platformData := c.GetAgentPlatformData()
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
	if c.GetOwner() == VTAP_OWNER_DEEPFLOW {
		functionSet := mapset.NewSet()
		for _, functionStr := range strings.Split(VTAP_ALL_LICENSE_FUNCTIONS, ",") {
			function, err := strconv.Atoi(functionStr)
			if err != nil {
				log.Warningf("const lincense function (%s) substring (%s) to int failed, err: %s", VTAP_ALL_LICENSE_FUNCTIONS, functionStr, err)
				continue
			}
			functionSet.Add(function)
		}
		return functionSet
	}
	return c.licenseFunctionSet
}

func (c *VTapCache) GetVTapType() int {
	return c.vTapType
}

func (c *VTapCache) GetVTapEnabled() int {
	return c.enable
}

func (c *VTapCache) GetVTapState() int {
	return c.state
}

func (c *VTapCache) GetOwner() string {
	if c.owner != nil {
		return *c.owner
	}
	return ""
}

func (c *VTapCache) UpdateOwner(isOwnerCluster bool) {
	if !isOwnerCluster {
		return
	}
	c.owner = proto.String(VTAP_OWNER_DEEPFLOW)
}

func (c *VTapCache) GetVTapHost() string {
	if c.name != nil {
		return *c.name
	}
	return ""
}

func (c *VTapCache) GetVTapRawHostname() string {
	if c.rawHostname != nil {
		return *c.rawHostname
	}
	return ""

}

func (c *VTapCache) UpdateVTapRawHostname(name string) {
	if name != "" {
		c.rawHostname = &name
	}
}

func (c *VTapCache) GetConfigSyncInterval() int {
	config := c.GetVTapConfig()
	if config == nil {
		return DefaultSyncInterval
	}
	if config.SyncInterval == nil {
		return DefaultSyncInterval
	}

	return *config.SyncInterval
}

func (c *VTapCache) GetUserConfig() *koanf.Koanf {
	config := c.GetVTapConfig()
	if config == nil {
		return koanf.New(".")
	}
	return config.GetUserConfig()
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

func (c *VTapCache) GetVTapGroupShortID() string {
	if c.vTapGroupShortID != nil {
		return *c.vTapGroupShortID
	}
	return ""
}

func (c *VTapCache) updateVTapGroupLcuuid(lcuuid string) {
	c.vTapGroupLcuuid = &lcuuid
}

func (c *VTapCache) updateVTapGroupShortID(shortID string) {
	c.vTapGroupShortID = &shortID
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

func (c *VTapCache) GetExternalAgentHTTPProxyEnabledConfig() int {
	v := c.vTapInfo
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
	if config.ExternalAgentHTTPProxyEnabled == nil {
		return 0
	}

	return *config.ExternalAgentHTTPProxyEnabled
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

func (c *VTapCache) GetCurrentK8SImage() string {
	if c.currentK8sImage != nil {
		return *c.currentK8sImage
	}
	return ""
}

func (c *VTapCache) updateCurrentK8SImage(currentK8sImage string) {
	c.currentK8sImage = &currentK8sImage
}

func (c *VTapCache) GetLicenseType() int {
	return c.licenseType
}

func (c *VTapCache) GetTapMode() int {
	return c.tapMode
}

func (c *VTapCache) updateTapMode(tapMode int) {
	c.tapMode = tapMode
}

func (c *VTapCache) GetTeamID() int {
	return c.teamID
}

func (c *VTapCache) updateTeamID(teamID int) {
	c.teamID = teamID
}

func (c *VTapCache) updateOrganizeID(organizeID int) {
	c.organizeID = organizeID
}

func (c *VTapCache) GetOrganizeID() int {
	return c.organizeID
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
	v := c.vTapInfo
	log.Infof(v.Logf(
		"modify vtap(%s) exception %d to %d",
		c.GetVTapHost(), c.GetExceptions(), exceptions))
	atomic.StoreInt64(&c.exceptions, int64(exceptions))
}

func (c *VTapCache) UpdateSystemInfoFromGrpc(cpuNum int, memorySize int64, arch, os, kernelVersion, processName, currentK8sImage string) {
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
	if currentK8sImage != "" {
		c.updateCurrentK8SImage(currentK8sImage)
	}
}

func (c *VTapCache) UpdateCtrlMacFromGrpc(ctrlMac string) {
	v := c.vTapInfo
	if c.GetCtrlMac() == "" || c.GetCtrlMac() != ctrlMac {
		c.updateCtrlMac(ctrlMac)
		log.Infof(v.Logf("grpc modify vtap(%s) ctrl_mac (%s) to (%s)",
			c.GetVTapHost(), c.GetCtrlMac(), ctrlMac))
	}
}

func (c *VTapCache) updateCtrlMacFromDB(ctrlMac string) {
	v := c.vTapInfo
	if c.GetCtrlMac() == "" && ctrlMac != "" {
		c.updateCtrlMac(ctrlMac)
		log.Infof(v.Logf("db modify vtap(%s) ctrl_mac (%s) to (%s)",
			c.GetVTapHost(), c.GetCtrlMac(), ctrlMac))
	}
}

func (c *VTapCache) init() {
	c.modifyVTapCache()
	c.initVTapPodDomains()
	c.initVTapConfig()
}

func (c *VTapCache) modifyVTapCache() {
	v := c.vTapInfo
	if c.state == VTAP_STATE_PENDING {
		c.enable = 0
	}
	var ok bool
	c.regionID = v.GetRegionIDByLcuuid(c.GetRegion())
	vTapType := c.GetVTapType()
	if vTapType == VTAP_TYPE_POD_HOST || vTapType == VTAP_TYPE_POD_VM {
		c.podClusterID, ok = v.lcuuidToPodClusterID[c.GetLcuuid()]
		if ok == false {
			log.Warningf(v.Logf("vtap(%s) not found podClusterID", c.GetVTapHost()))
		}
		c.VPCID, ok = v.lcuuidToVPCID[c.GetLcuuid()]
		if ok == false {
			log.Warningf(v.Logf("vtap(%s) not found VPCID", c.GetVTapHost()))
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
			log.Warningf(v.Logf("vtap(%s) not found VPCID", c.GetVTapHost()))
		}
	} else if vTapType == VTAP_TYPE_HYPER_V && v.hypervNetworkHostIds.Contains(c.GetLaunchServerID()) {
		c.vTapType = VTAP_TYPE_HYPER_V_NETWORK
		c.VPCID, ok = v.hostIDToVPCID[c.GetLaunchServerID()]
		if ok == false {
			log.Warningf(v.Logf("vtap(%s) not found VPCID", c.GetVTapHost()))
		}
	} else if vTapType == VTAP_TYPE_KVM || vTapType == VTAP_TYPE_HYPER_V {
		c.VPCID, ok = v.hostIDToVPCID[c.GetLaunchServerID()]
		if ok == false {
			log.Warningf(v.Logf("vtap(%s) not found VPCID", c.GetVTapHost()))
		}
	}
}

func (c *VTapCache) initVTapPodDomains() {
	c.podDomains = c.vTapInfo.getVTapPodDomains(c)
}

func (c *VTapCache) initVTapConfig() {
	v := c.vTapInfo
	realConfig := VTapConfig{}
	vtapGroupLcuuid := c.GetVTapGroupLcuuid()

	if config, ok := v.vtapGroupLcuuidToConfiguration[vtapGroupLcuuid]; ok {
		realConfig = deepcopy.Copy(*config).(VTapConfig)
		realConfig.UserConfig = config.GetUserConfig()
	} else {
		if v.realDefaultConfig != nil {
			realConfig = deepcopy.Copy(*v.realDefaultConfig).(VTapConfig)
			realConfig.UserConfig = koanf.New(".")
		}

	}

	c.modifyVTapConfigByLicense(&realConfig)
	realConfig.modifyConfig(v)
	realConfig.modifyUserConfig(c)
	c.updateVTapConfig(&realConfig)
}

func (c *VTapCache) updateVTapConfigFromDB() {
	v := c.vTapInfo
	newConfig := VTapConfig{}

	config, ok := v.vtapGroupLcuuidToConfiguration[c.GetVTapGroupLcuuid()]
	if ok {
		newConfig = deepcopy.Copy(*config).(VTapConfig)
		newConfig.UserConfig = config.GetUserConfig()
	} else {
		if v.realDefaultConfig != nil {
			newConfig = deepcopy.Copy(*v.realDefaultConfig).(VTapConfig)
			newConfig.UserConfig = koanf.New(".")
		}
	}

	oldConfig := c.GetVTapConfig()
	if oldConfig != nil {
		// 采集器配置发生变化 重新生成平台数据
		if newConfig.Domains != oldConfig.Domains || newConfig.PodClusterInternalIP != oldConfig.PodClusterInternalIP {
			v.setVTapChangedForPD()
		}
	}

	c.modifyVTapConfigByLicense(&newConfig)
	newConfig.modifyConfig(v)
	newConfig.modifyUserConfig(c)
	c.updateVTapConfig(&newConfig)
}

func (c *VTapCache) GetConfigTapMode() int {
	config := c.GetVTapConfig()
	if config == nil {
		return -1
	}
	if config.TapMode == nil {
		return -1
	}
	return *config.TapMode
}

func (c *VTapCache) updateVTapCacheFromDB(vtap *mysqlmodel.VTap) {
	v := c.vTapInfo
	c.updateCtrlMacFromDB(vtap.CtrlMac)
	c.state = vtap.State
	c.enable = vtap.Enable
	c.updateLicenseFunctions(vtap.LicenseFunctions)
	c.updateTapMode(vtap.TapMode)
	c.updateTeamID(vtap.TeamID)
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
	c.modifyVTapCache()
	// 采集器组变化 重新生成平台数据
	if c.GetVTapGroupLcuuid() != vtap.VtapGroupLcuuid {
		c.updateVTapGroupLcuuid(vtap.VtapGroupLcuuid)
		c.updateVTapGroupShortID(v.vtapGroupLcuuidToShortID[vtap.VtapGroupLcuuid])
		v.setVTapChangedForPD()
	}
	c.updateVTapConfigFromDB()
	newPodDomains := v.getVTapPodDomains(c)
	oldPodDomains := c.getPodDomains()
	// podDomain 发生变化重新生成平台数据
	if !SliceEqual[string](newPodDomains, oldPodDomains) {
		c.updatePodDomains(newPodDomains)
		v.setVTapChangedForPD()
	}
	if c.GetConfigTapMode() != c.GetTapMode() {
		log.Warningf(v.Logf("config tap_mode(%d) is not equal to vtap(%s) tap_mode(%d)", c.GetConfigTapMode(), c.GetKey(), c.GetTapMode()))
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
	v := c.vTapInfo
	config := c.config.Load()
	if config == nil {
		log.Warningf(v.Logf("vtap(%s) no config", c.GetVTapHost()))
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
	v := c.vTapInfo
	platformData := c.PlatformData.Load()
	if platformData == nil {
		log.Warningf(v.Logf("vtap(%s) no platformData", c.GetVTapHost()))
		return nil
	}
	return platformData.(*metadata.PlatformData)
}

func (c *VTapCache) setAgentPlatformData(d *agentmetadata.PlatformData) {
	if d == nil {
		return
	}
	c.AgentPlatformData.Store(d)
}

func (c *VTapCache) GetAgentPlatformData() *agentmetadata.PlatformData {
	v := c.vTapInfo
	platformData := c.AgentPlatformData.Load()
	if platformData == nil {
		log.Warningf(v.Logf("agent(%s) no platformData", c.GetVTapHost()))
		return nil
	}
	return platformData.(*agentmetadata.PlatformData)
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

func (c *VTapCache) setAgentLocalSegments(segments []*agent.Segment) {
	c.agentLocalSegments = segments
}

func (c *VTapCache) GetAgentLocalSegments() []*agent.Segment {
	return c.agentLocalSegments
}

func (c *VTapCache) setAgentRemoteSegments(segments []*agent.Segment) {
	c.agentRemoteSegments = segments
}

func (c *VTapCache) GetAgentRemoteSegments() []*agent.Segment {
	return c.agentRemoteSegments
}

func (c *VTapCache) UpdateLastSyncBytes(bytes uint64) {
	c.lastSyncBytes = bytes
	c.grpcBufferSize = c.calculateGRPCBytes()
}

func (c *VTapCache) UpdateLastPushBytes(bytes uint64) {
	c.lastPushBytes = bytes
	c.grpcBufferSize = c.calculateGRPCBytes()
}

func (c *VTapCache) UpdateLastGPIDSyncBytes(bytes uint64) {
	c.lastGPIDSyncBytes = bytes
	c.grpcBufferSize = c.calculateGRPCBytes()
}

func (c *VTapCache) calculateGRPCBytes() uint64 {
	return common.CalculateBufferSize(max(c.lastSyncBytes, c.lastPushBytes, c.lastGPIDSyncBytes))
}

func (c *VTapCache) GetGRPCBufferSize() uint64 {
	return c.grpcBufferSize
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
