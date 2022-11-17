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

package service

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/mohae/deepcopy"

	. "github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

var newConfigManager *GroupConfigMananger
var detailConfigManager *GroupConfigMananger

func init() {
	newConfigManager = newGroupConfigMananger(true)
	detailConfigManager = newGroupConfigMananger(false)
}

func getGroups() []Data {
	var vtapGroups []mysql.VTapGroup
	mysql.Db.Find(&vtapGroups)
	values := make([]Data, 0, len(vtapGroups))
	for _, vtapGroup := range vtapGroups {
		values = append(values,
			Data{
				Label: vtapGroup.Name,
				Value: vtapGroup.Lcuuid,
			},
		)
	}

	return values
}

func getTapTypes() []Data {
	var tapTypes []mysql.TapType
	mysql.Db.Find(&tapTypes)
	values := []Data{
		Data{Label: "全部", Value: 0},
		Data{Label: "无", Value: -1},
	}
	for _, tapType := range tapTypes {
		values = append(values,
			Data{Label: tapType.Name, Value: tapType.Value},
		)
	}

	return values
}

func getDomains() []Data {
	var domains []mysql.Domain
	mysql.Db.Find(&domains)
	values := []Data{
		Data{Label: "全部", Value: "0"},
	}
	for _, domain := range domains {
		values = append(values,
			Data{Label: domain.Name, Value: domain.Lcuuid},
		)
	}

	return values
}

type DataList []Data

var switchData = DataList{
	Data{Value: 0, Label: "关闭"},
	Data{Value: 1, Label: "开启"},
}

var whetherData = DataList{
	Data{Value: 0, Label: "否"},
	Data{Value: 1, Label: "是"},
}

func (d DataList) getLabelByValue(value interface{}) string {
	for _, data := range d {
		if data.Value == value {
			return data.Label
		}
	}
	return ""
}

type ConfigLabel struct {
	label       string
	SectionName string                 `json:"section_name"`
	Configs     map[string]*ConfigBase `json:"section_config"`
}

func newConfigLabel(label string, name string) *ConfigLabel {
	return &ConfigLabel{
		label:       label,
		SectionName: name,
		Configs:     make(map[string]*ConfigBase),
	}
}

func (c *ConfigLabel) addConfig(name string, config *ConfigBase) {
	c.Configs[name] = config
}

func (c *ConfigLabel) getConfig(name string) *ConfigBase {
	return c.Configs[name]
}

func (c *ConfigLabel) String() string {
	jsons, err := json.Marshal(c)
	if err != nil {
		log.Error(err)
		return ""
	}

	return string(jsons)
}

type Rules struct {
	RealRules []string `json:"realRules,omitempty"`
	IsNumber  bool     `json:"isNumber,omitempty"`
	Multiple  bool     `json:"multiple,omitempty"`
	Required  bool     `json:"required,omitempty"`
}

type Data struct {
	Value interface{} `json:"value"`
	Label string      `json:"label"`
}

type ConfigBase struct {
	Type        string      `json:"type,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Rules       Rules       `json:"rules,omitempty"`
	Help        string      `json:"help,omitempty"`
	Data        []Data      `json:"data,omitempty"`
	Value       interface{} `json:"value,omitempty"`
	Disabled    bool        `json:"disabled,omitempty"`
	Label       string      `json:"label,omitempty"`
	Unit        string      `json:"unit,omitempty"`
	labelName   string
	jsonTag     string
}

func (b *ConfigBase) setDisabled() {
	b.Disabled = true
}

func (b *ConfigBase) setData(data []Data) {
	b.Data = data
}

func (b *ConfigBase) setValue(value interface{}) {
	b.Value = value
}

var configFuns = []*ConfigBase{
	GroupConfigFun(),
	// resource_limit_label
	MaxMemoryFun(),
	SysFreeMemoryLimitFun(),
	MaxCpusFun(),
	MaxNpbBpsFun(),
	MaxCollectPpsFun(),
	BandwidthProbeIntervalFun(),
	MaxTxBandwidthFun(),
	LogThresholdFun(),
	LogLevelFun(),
	LogFileSizeFun(),
	ThreadThresholdFun(),
	ProcessThresholdFun(),
	//basic_configuration_params_label
	TapInterfaceRegexFun(),
	CaptureBpfFun(),
	CapturePacketSizeFun(),
	CaptureSocketTypeFun(),
	TapModeFun(),
	DecapTypeFun(),
	IfMacSourceFun(),
	VmXmlPathFun(),
	SyncIntervalFun(),
	MaxEscapeSecondsFun(),
	MtuFun(),
	OutputVlanFun(),
	NatIpEnabledFun(),
	LogRetentionFun(),
	ExtraNetnsRegexFun(),
	ProxyControllerPortFun(),
	ProxyControllerIPFun(),
	AnalyzerPortFun(),
	AnalyzerIPFun(),
	//statistics_configuration_params_label
	CollectorSocketTypeFun(),
	CompressorSocketTypeFun(),
	HttpLogProxyClientFun(),
	HttpLogTraceIdFun(),
	HttpLogSpanIdFun(),
	HttpLogXRequestIdFun(),
	L7LogPacketSizeFun(),
	L4LogCollectNpsThresholdFun(),
	L7LogCollectNpsThresholdFun(),
	//npb_configuration_params_label
	NpbSocketTypeFun(),
	NpbVlanModeFun(),
	//basic_func_switch_label
	PlatformEnabledFun(),
	RsyslogEnabledFun(),
	NTPEnabledFun(),
	DomainsFun(),
	ExtraPodIpEnableFun(),
	//statistics_func_switch_label
	CollectorEnabledFun(),
	InactiveServerPortEnabledFun(),
	InactiveIPEnabledFun(),
	L4PerformanceEnabledFun(),
	L7MetricsEnabledFun(),
	VtapFlow1SEnabledFun(),
	L4LogTapTypesFun(),
	L7LogStoreTapTypesFun(),
	ExternalAgentHttpProxyEnabledFun(),
	ExternalAgentHttpProxyPortFun(),
	//npb_func_switch_label
	NpbDedupEnabledFun(),
}

const (
	group_label                           = "group_label"
	resource_limit_label                  = "resource_limit_label"
	basic_configuration_params_label      = "basic_configuration_params_label"
	statistics_configuration_params_label = "statistics_configuration_params_label"
	npb_configuration_params_label        = "npb_configuration_params_label"
	basic_func_switch_label               = "basic_func_switch_label"
	statistics_func_switch_label          = "statistics_func_switch_label"
	npb_func_switch_label                 = "npb_func_switch_label"
)

var labelNames = []string{
	group_label,
	resource_limit_label,
	basic_configuration_params_label,
	statistics_configuration_params_label,
	npb_configuration_params_label,
	basic_func_switch_label,
	statistics_func_switch_label,
	npb_func_switch_label,
}

var sectionNameMap = map[string]string{
	group_label:                           "",
	resource_limit_label:                  "资源限制",
	basic_configuration_params_label:      "基础配置参数",
	statistics_configuration_params_label: "全景图配置参数",
	npb_configuration_params_label:        "包分发配置参数",
	basic_func_switch_label:               "基础功能开关",
	statistics_func_switch_label:          "全景图功能开关",
	npb_func_switch_label:                 "包分发功能开关",
}

func GroupConfigFun() *ConfigBase {
	rules := Rules{
		Required: true,
	}
	return &ConfigBase{
		Type:      "select",
		Label:     "采集器组",
		Value:     "",
		Data:      nil,
		Rules:     rules,
		jsonTag:   "VTAP_GROUP_LCUUID",
		labelName: group_label,
	}
}

func MaxMemoryFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigMem"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "内存限制",
		Rules:       rules,
		Unit:        "M字节",
		Placeholder: fmt.Sprintf("默认配置: %d，值域[128, 100000]", DefaultMaxMemory),
		jsonTag:     "MAX_MEMORY",
		labelName:   resource_limit_label,
		Help:        "对于专属服务器采集器无效，对于容器类型的 deepflow-agent 也无效",
	}
}

func SysFreeMemoryLimitFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"SYS_FREE_MEMORY_LIMIT"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "系统空闲内存限制",
		Rules:       rules,
		Unit:        "%",
		Placeholder: fmt.Sprintf("默认配置: %d，值域[0, 100]", DefaultSysFreeMemoryLimit),
		Help:        "系统空闲内存的最低百分比，当比例低于该值的90%时采集器将重启",
		jsonTag:     "SYS_FREE_MEMORY_LIMIT",
		labelName:   resource_limit_label,
	}
}

func MaxCpusFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigCpu"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "CPU限制",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 100000]", DefaultMaxCPUs),
		jsonTag:     "MAX_CPUS",
		labelName:   resource_limit_label,
		Help:        "对于专属服务器采集器无效，对于容器类型的 deepflow-agent 也无效",
		Unit:        "逻辑核",
	}
}

func MaxNpbBpsFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigNbpmbps"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "分发流限速",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 10000]", DefaultMaxNpbBps/1000000),
		Unit:        "Mbps",
		jsonTag:     "MAX_NPB_BPS",
		labelName:   resource_limit_label,
	}
}

func MaxCollectPpsFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigKpps"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "采集包限速",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 1000000]", DefaultMaxCollectPps/1000),
		Unit:        "Kpps",
		jsonTag:     "MAX_COLLECT_PPS",
		labelName:   resource_limit_label,
		Help:        "对于专属服务器采集器无效",
	}
}

func BandwidthProbeIntervalFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigBandwidthProbeInterval"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "分发熔断监控间隔",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 60]", DefaultBandwidthProbeInterval),
		Unit:        "秒",
		Help:        "分发接口出方向流量速率的监控间隔",
		jsonTag:     "BANDWIDTH_PROBE_INTERVAL",
		labelName:   resource_limit_label,
	}
}

func MaxTxBandwidthFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigMaxTxBandwidth"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "分发熔断阈值",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 10000]", DefaultBandwidthProbeInterval/1000000),
		Unit:        "Mbps",
		Help: "当分发接口出方向达到或超过阈值时将停止分发，" +
			"当连续5个监控间隔低于(阈值-分发流量限制)*90%时恢复分发。" +
			"注意：配置此值必须大于分发流限速，输入0表示关闭此功能。",
		jsonTag:   "MAX_TX_BANDWIDTH",
		labelName: resource_limit_label,
	}
}

func LogThresholdFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapLogThreshold"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "日志发送速率",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 10000]", DefaultLogThreshold),
		Unit:        "条/小时",
		Help:        "设置为0表示不限速",
		jsonTag:     "LOG_THRESHOLD",
		labelName:   resource_limit_label,
	}
}

func LogLevelFun() *ConfigBase {
	data := []Data{
		Data{Value: "DEBUG", Label: "DEBUG"},
		Data{Value: "INFO", Label: "INFO"},
		Data{Value: "WARNING", Label: "WARNING"},
		Data{Value: "ERROR", Label: "ERROR"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "日志打印等级",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultLogLevel),
		jsonTag:     "LOG_LEVEL",
		labelName:   resource_limit_label,
	}
}

func LogFileSizeFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"LOG_FILE_SIZE"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "日志文件大小",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 10000]", DefaultLogFileSize),
		Unit:        "M字节",
		jsonTag:     "LOG_FILE_SIZE",
		labelName:   resource_limit_label,
	}
}

func ThreadThresholdFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"THREAD_THRESHOLD"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "线程数限制",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 1000]", DefaultThreadThreshold),
		Unit:        "个",
		jsonTag:     "THREAD_THRESHOLD",
		labelName:   resource_limit_label,
	}
}

func ProcessThresholdFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"PROCESS_THRESHOLD"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "进程数限制",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 100]", DefaultProcessThreshold),
		Unit:        "个",
		jsonTag:     "PROCESS_THRESHOLD",
		labelName:   resource_limit_label,
	}
}

func TapInterfaceRegexFun() *ConfigBase {
	return &ConfigBase{
		Type:        "text",
		Label:       "采集网口",
		Placeholder: fmt.Sprintf("默认配置: %s，长度范围[1, 512]", DefaultTapInterfaceRegex),
		jsonTag:     "TAP_INTERFACE_REGEX",
		labelName:   basic_configuration_params_label,
	}
}

func CaptureBpfFun() *ConfigBase {
	return &ConfigBase{
		Type:        "text",
		Label:       "流量过滤",
		Placeholder: "默认配置: 全采集，长度范围[1, 512]",
		Help:        "参考BPF语法：https://biot.com/capstats/bpf.html",
		jsonTag:     "CAPTURE_BPF",
		labelName:   basic_configuration_params_label,
	}
}

func ExtraNetnsRegexFun() *ConfigBase {
	return &ConfigBase{
		Type:        "text",
		Label:       "采集NETNS",
		Placeholder: "默认配置: ，长度范围[0, 65535]",
		Help:        "正则表达式，除root之外的网络命名空间名称，常用于多租户网络隔离的场景",
		jsonTag:     "CAPTURE_BPF",
		labelName:   basic_configuration_params_label,
	}
}

func ProxyControllerPortFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"ProxyControllerPort"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "控制器通信端口",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，[1, 65535]", DefaultProxyControllerPort),
		jsonTag:     "PROXY_CONTROLLER_PORT",
		labelName:   basic_configuration_params_label,
	}
}

func ProxyControllerIPFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"isAllIP"},
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "控制器IP",
		Rules:       rules,
		Placeholder: "默认配置: 空",
		jsonTag:     "PROXY_CONTROLLER_IP",
		Help:        "固定使用此控制器IP",
		labelName:   basic_configuration_params_label,
	}
}

func AnalyzerPortFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"AnalyzerPort"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "数据节点通信端口",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 65535]", DefaultAnalyzerPort),
		jsonTag:     "ANALYZER_PORT",
		labelName:   basic_configuration_params_label,
	}
}

func AnalyzerIPFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"isAllIP"},
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "数据节点IP",
		Rules:       rules,
		Placeholder: "默认配置: 空",
		jsonTag:     "ANALYZER_IP",
		Help:        "固定使用此数据节点IP",
		labelName:   basic_configuration_params_label,
	}
}

func CapturePacketSizeFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"CAPTURE_PACKET_SIZE"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "采集包长",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，长度范围[128, 65535]", DefaultCapturePacketSize),
		Help:        "DPDK环境目前不支持此参数",
		Unit:        "字节",
		jsonTag:     "CAPTURE_PACKET_SIZE",
		labelName:   basic_configuration_params_label,
	}
}

func CaptureSocketTypeFun() *ConfigBase {
	data := []Data{
		Data{Value: 0, Label: "自适应"},
		Data{Value: 2, Label: "AF_PACKET V2"},
		Data{Value: 3, Label: "AF_PACKET V3"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "流量采集API",
		Data:        data,
		Placeholder: "默认配置: 自适应",
		Help:        "Linux环境中的流量采集方式",
		jsonTag:     "CAPTURE_SOCKET_TYPE",
		labelName:   basic_configuration_params_label,
	}
}

func TapModeFun() *ConfigBase {
	data := []Data{
		Data{Value: 0, Label: "本地 (0)"},
		Data{Value: 1, Label: "虚拟镜像 (1)"},
		Data{Value: 2, Label: "物理物理 (2)"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "流量采集方式",
		Data:        data,
		Placeholder: "默认配置: 本地 (0)",
		Help:        "ESXi 采集器选择虚拟镜像，专属采集器选择物理镜像",
		jsonTag:     "TAP_MODE",
		labelName:   basic_configuration_params_label,
	}
}

func DecapTypeFun() *ConfigBase {
	rules := Rules{Multiple: true}
	data := []Data{
		Data{Value: 0, Label: "无"},
		Data{Value: 1, Label: "VXLAN"},
		Data{Value: 2, Label: "IPIP"},
		Data{Value: 3, Label: "GRE"},
	}
	return &ConfigBase{
		Type:        "select-allCheck",
		Label:       "解封装隧道类型",
		Rules:       rules,
		Data:        data,
		Placeholder: "默认配置: VXLAN,IPIP",
		jsonTag:     "DECAP_TYPE",
		labelName:   basic_configuration_params_label,
	}
}

func IfMacSourceFun() *ConfigBase {
	data := []Data{
		Data{Value: 0, Label: "接口MAC"},
		Data{Value: 1, Label: "接口名称"},
		Data{Value: 2, Label: "虚拟机XML"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "虚拟机MAC解析",
		Data:        data,
		Placeholder: "默认配置: 接口MAC",
		Help:        "KVM类型采集器获取虚拟机真实MAC地址的方式",
		jsonTag:     "IF_MAC_SOURCE",
		labelName:   basic_configuration_params_label,
	}
}

func VmXmlPathFun() *ConfigBase {
	rules := Rules{RealRules: []string{"xmlFolder"}}
	return &ConfigBase{
		Type:        "text",
		Label:       "虚拟机XML文件夹",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %s，长度范围[0, 100]", DefaultVMXMLPath),
		jsonTag:     "VM_XML_PATH",
		labelName:   basic_configuration_params_label,
	}
}

func SyncIntervalFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"vtapConfigSyncInterval"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "最长同步间隔",
		Unit:        "秒",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[10, 3600]", DefaultSyncInterval),
		Help:        "当资源信息变更时，策略同步更新的最长时间",
		jsonTag:     "SYNC_INTERVAL",
		labelName:   basic_configuration_params_label,
	}
}

func MaxEscapeSecondsFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"longEscapeTime"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "最长逃逸时间",
		Unit:        "秒",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[600, 2592000]", DefaultMaxEscapeSeconds),
		jsonTag:     "MAX_ESCAPE_SECONDS",
		labelName:   basic_configuration_params_label,
	}
}

func MtuFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"UDP_MTU"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "UDP最大MTU",
		Unit:        "字节",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[500, 10000]", DefaultMtu),
		jsonTag:     "MTU",
		labelName:   basic_configuration_params_label,
	}
}

func OutputVlanFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"UDP_VLAN"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "裸UDP外层VLAN",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[0, 4095]", DefaultOutputVlan),
		Help:        "0表示不携带VLAN标签",
		jsonTag:     "OUTPUT_VLAN",
		labelName:   basic_configuration_params_label,
	}
}

func NatIpEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "否请求NAT IP",
		Data:        whetherData,
		Placeholder: fmt.Sprintf("默认配置: %s", whetherData.getLabelByValue(DefaultNatIPEnabled)),
		jsonTag:     "NAT_IP_ENABLED",
		labelName:   basic_configuration_params_label,
	}
}

func LogRetentionFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"logRention"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "日志存储时长",
		Unit:        "天",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[7, 365]", DefaultLogRetention),
		jsonTag:     "LOG_RETENTION",
		labelName:   basic_configuration_params_label,
	}
}

func CollectorSocketTypeFun() *ConfigBase {
	data := []Data{
		Data{Value: "TCP", Label: "TCP"},
		Data{Value: "UDP", Label: "UDP"},
		Data{Value: "FILE", Label: "FILE"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "数据套接字",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultCollectorSocketType),
		jsonTag:     "COLLECTOR_SOCKET_TYPE",
		labelName:   statistics_configuration_params_label,
	}
}

func CompressorSocketTypeFun() *ConfigBase {
	data := []Data{
		Data{Value: "TCP", Label: "TCP"},
		Data{Value: "UDP", Label: "UDP"},
		Data{Value: "RAW_UDP", Label: "裸UDP"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "PCAP套接字",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultCompressorSocketType),
		jsonTag:     "COMPRESSOR_SOCKET_TYPE",
		labelName:   statistics_configuration_params_label,
	}
}

func HttpLogProxyClientFun() *ConfigBase {
	data := []Data{
		Data{Value: "X-Forwarded-For", Label: "X-Forwarded-For"},
		Data{Value: "关闭", Label: "关闭"},
	}
	return &ConfigBase{
		Type:        "select-create",
		Label:       "HTTP日志代理客户端",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultHTTPLogProxyClient),
		Help:        "可编辑，关闭为保留字",
		jsonTag:     "HTTP_LOG_PROXY_CLIENT",
		labelName:   statistics_configuration_params_label,
	}
}

func HttpLogTraceIdFun() *ConfigBase {
	data := []Data{
		Data{Value: "关闭", Label: "关闭"},
		Data{Value: "traceparent", Label: "traceparent"},
		Data{Value: "X-B3-TraceId", Label: "X-B3-TraceId"},
		Data{Value: "uber-trace-id", Label: "uber-trace-id"},
		Data{Value: "sw6", Label: "sw6"},
		Data{Value: "sw8", Label: "sw8"},
	}
	return &ConfigBase{
		Type:        "select-create",
		Label:       "应用流日志TraceID",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultHTTPLogTraceID),
		Help:        "可编辑，支持输入自定义值或逗号分隔的多个值，关闭为保留字；支持HTTP、Dubbo",
		jsonTag:     "HTTP_LOG_TRACE_ID",
		labelName:   statistics_configuration_params_label,
	}
}

func HttpLogSpanIdFun() *ConfigBase {
	data := []Data{
		Data{Value: "关闭", Label: "关闭"},
		Data{Value: "traceparent", Label: "traceparent"},
		Data{Value: "X-B3-TraceId", Label: "X-B3-TraceId"},
		Data{Value: "uber-trace-id", Label: "uber-trace-id"},
		Data{Value: "sw6", Label: "sw6"},
		Data{Value: "sw8", Label: "sw8"},
	}
	return &ConfigBase{
		Type:        "select-create",
		Label:       "应用流日志SpanID",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultHTTPLogSpanID),
		Help:        "可编辑，支持输入自定义值或逗号分隔的多个值，关闭为保留字；支持HTTP、Dubbo",
		jsonTag:     "HTTP_LOG_TRACE_ID",
		labelName:   statistics_configuration_params_label,
	}
}

func HttpLogXRequestIdFun() *ConfigBase {
	data := []Data{
		Data{Value: "关闭", Label: "关闭"},
		Data{Value: "X-Request-ID", Label: "X-Request-ID"},
		Data{Value: "X-Bfe-Log-Id", Label: "X-Bfe-Log-Id"},
		Data{Value: "uber-trace-id", Label: "uber-trace-id"},
		Data{Value: "Stgw-request-id", Label: "Stgw-request-id"},
	}
	return &ConfigBase{
		Type:        "select-create",
		Label:       "HTTP日志XRequestID",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultHTTPLogXRequestID),
		Help:        "可编辑，关闭为保留字",
		jsonTag:     "HTTP_LOG_X_REQUEST_ID",
		labelName:   statistics_configuration_params_label,
	}
}

func L7LogPacketSizeFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"l7LogPacketSize"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "应用日志解析包长",
		Unit:        "字节",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[256, 1500]", DefaultL7LogPacketSize),
		Help:        "采集HTTP、DNS日志时的解析的包长，注意不要超过采集包长参数",
		jsonTag:     "L7_LOG_PACKET_SIZE",
		labelName:   statistics_configuration_params_label,
	}
}

func L4LogCollectNpsThresholdFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"l4LogCollectNpsThreshold"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "流日志采集速率",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[100, 1000000]", DefaultL4LogCollectNpsThreshold),
		Help:        "每秒采集的流日志条数，超过以后采样",
		jsonTag:     "L4_LOG_COLLECT_NPS_THRESHOLD",
		labelName:   statistics_configuration_params_label,
	}
}

func L7LogCollectNpsThresholdFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"l7LogCollectNpsThreshold"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "应用日志采集速率",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[100, 1000000]", DefaultL7LogCollectNpsThreshold),
		Help:        "每秒采集的HTTP和DNS日志条数，超过以后采样",
		jsonTag:     "L7_LOG_COLLECT_NPS_THRESHOLD",
		labelName:   statistics_configuration_params_label,
	}
}

func NpbSocketTypeFun() *ConfigBase {
	data := []Data{
		Data{Value: "UDP", Label: "UDP"},
		Data{Value: "RAW_UDP", Label: "裸UDP"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "分发套接字",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", DefaultNpbSocketType),
		jsonTag:     "NPB_SOCKET_TYPE",
		labelName:   npb_configuration_params_label,
	}
}

func NpbVlanModeFun() *ConfigBase {
	data := []Data{
		Data{Value: 0, Label: "无"},
		Data{Value: 1, Label: "802.1Q"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "内层附加头",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", "无"),
		jsonTag:     "NPB_VLAN_MODE",
		labelName:   npb_configuration_params_label,
	}
}

func PlatformEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "同步资源信息",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultPlatformEnabled)),
		jsonTag:     "PLATFORM_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func RsyslogEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "日志发送",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultRsyslogEnabled)),
		jsonTag:     "RSYSLOG_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func NTPEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "时钟同步",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultNtpEnabled)),
		Help:        "仅用于采集器进程内部时钟计算，开启后不会影响采集器所在操作系统的时钟",
		jsonTag:     "NTP_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func DomainsFun() *ConfigBase {
	rules := Rules{
		Multiple: true,
	}
	return &ConfigBase{
		Type:        "select-allCheck",
		Label:       "云平台资源信息下发",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %s", "全部"),
		jsonTag:     "DOMAINS",
		labelName:   basic_func_switch_label,
	}
}

func ExtraPodIpEnableFun() *ConfigBase {
	data := []Data{
		Data{Value: 0, Label: "所有集群"},
		Data{Value: 1, Label: "采集器所在集群"},
	}
	return &ConfigBase{
		Type:        "select",
		Label:       "容器集群内部IP下发",
		Data:        data,
		Placeholder: fmt.Sprintf("默认配置: %s", "所有集群"),
		Help:        "容器集群内部IP特指POD IP和服务的Cluster IP",
		jsonTag:     "POD_CLUSTER_INTERNAL_IP",
		labelName:   basic_func_switch_label,
	}
}

func CollectorEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultCollectorEnabled)),
		jsonTag:     "COLLECTOR_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func InactiveServerPortEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "非活跃端口指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultInactiveServerPortEnabled)),
		jsonTag:     "INACTIVE_SERVER_PORT_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func InactiveIPEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "非活跃IP指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultInactiveIPEnabled)),
		jsonTag:     "INACTIVE_IP_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func L4PerformanceEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "网络性能指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultL4PerformanceEnabled)),
		Help:        "关闭时，采集器仅计算最基本的网络层吞吐指标量",
		jsonTag:     "L4_PERFORMANCE_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func L7MetricsEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "应用性能指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultL7MetricsEnabled)),
		jsonTag:     "L7_METRICS_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func VtapFlow1SEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "秒粒度指标数据",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultVTapFlow1sEnabled)),
		jsonTag:     "VTAP_FLOW_1S_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func L4LogTapTypesFun() *ConfigBase {
	rules := Rules{
		Multiple: true,
	}
	return &ConfigBase{
		Type:        "select-allCheck",
		Label:       "流日志开启采集点",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %s", "全部"),
		Help:        "全部和无与其他选项互斥",
		jsonTag:     "L4_LOG_TAP_TYPES",
		labelName:   basic_func_switch_label,
	}
}

func L7LogStoreTapTypesFun() *ConfigBase {
	rules := Rules{
		Multiple: true,
	}
	return &ConfigBase{
		Type:        "select-allCheck",
		Label:       "应用日志开启采集点",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %s", "全部"),
		Help:        "全部和无与其他选项互斥",
		jsonTag:     "L7_LOG_STORE_TAP_TYPES",
		labelName:   basic_func_switch_label,
	}
}

func ExternalAgentHttpProxyEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "数据集成服务",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultExternalAgentHTTPProxyEnabled)),
		jsonTag:     "EXTERNAL_AGENT_HTTP_PROXY_ENABLED",
		labelName:   basic_func_switch_label,
	}
}

func ExternalAgentHttpProxyPortFun() *ConfigBase {
	rules := Rules{
		RealRules: []string{"ExternalAgentHttpProxyPort"},
		IsNumber:  true,
	}
	return &ConfigBase{
		Type:        "text",
		Label:       "数据集成端口",
		Rules:       rules,
		Placeholder: fmt.Sprintf("默认配置: %d，值域[1, 65535]", DefaultExternalAgentHTTPProxyPort),
		jsonTag:     "EXTERNAL_AGENT_HTTP_PROXY_PORT",
		labelName:   basic_func_switch_label,
	}
}

func NpbDedupEnabledFun() *ConfigBase {
	return &ConfigBase{
		Type:        "select",
		Label:       "全局去重",
		Data:        switchData,
		Placeholder: fmt.Sprintf("默认配置: %s", switchData.getLabelByValue(DefaultNpbDedupEnabled)),
		jsonTag:     "NPB_DEDUP_ENABLED",
		labelName:   npb_func_switch_label,
	}
}

type GroupConfigMananger struct {
	Labels        []*ConfigLabel
	newConfigFlag bool
	configMap     map[string]*ConfigBase
}

func newGroupConfigMananger(newConfigFlag bool) *GroupConfigMananger {
	manager := &GroupConfigMananger{
		newConfigFlag: newConfigFlag,
		configMap:     make(map[string]*ConfigBase),
	}
	manager.initLabel()
	return manager
}

func (m *GroupConfigMananger) addConfig(name string, config *ConfigBase) {
	m.configMap[name] = config
}

func (m *GroupConfigMananger) getConfig(name string) *ConfigBase {
	return m.configMap[name]
}

func (m *GroupConfigMananger) addLabel(configLabel *ConfigLabel) {
	m.Labels = append(m.Labels, configLabel)
}

func (m *GroupConfigMananger) initLabel() {
	labelsMap := make(map[string]*ConfigLabel)
	for _, label := range labelNames {
		name, ok := sectionNameMap[label]
		if ok == false {
			log.Errorf("lable(%s) not found sectonName", label)
			continue
		}
		configLabel := newConfigLabel(label, name)
		m.addLabel(configLabel)
		labelsMap[label] = configLabel
	}

	for _, configFun := range configFuns {
		configLabel := labelsMap[configFun.labelName]
		if configLabel == nil {
			log.Errorf("label(%s) not found", configFun.labelName)
			continue
		}
		if configFun.jsonTag == "" {
			log.Errorf("config(%+v) does not configure jsonTag", configFun)
			continue
		}
		// The vtap group cannot be modified without creating a new configuration
		if configFun.jsonTag == "VTAP_GROUP_LCUUID" && m.newConfigFlag == false {
			configFun.setDisabled()
		}
		configLabel.addConfig(configFun.jsonTag, configFun)
		m.addConfig(configFun.jsonTag, configFun)
	}
}

func (m *GroupConfigMananger) getDefaultValue() {
	tapTypesData := getTapTypes()
	for _, name := range []string{"L4_LOG_TAP_TYPES", "L7_LOG_STORE_TAP_TYPES"} {
		config := m.getConfig(name)
		if config != nil {
			config.setData(tapTypesData)
		}
	}
	config := m.getConfig("VTAP_GROUP_LCUUID")
	if config != nil {
		config.setData(getGroups())
	}
	config = m.getConfig("DOMAINS")
	if config != nil {
		config.setData(getDomains())
	}
}

func (m *GroupConfigMananger) setConfigValue(config *mysql.VTapGroupConfiguration) {
	if config == nil {
		return
	}
	m.getDefaultValue()
	configElem := reflect.ValueOf(config).Elem()
	var err error
	for i := 0; i < configElem.NumField(); i++ {
		field := configElem.Type().Field(i)
		tagName := field.Tag.Get("json")
		if tagName == "" {
			continue
		}
		config := m.getConfig(tagName)
		if config == nil {
			continue
		}
		configValue := configElem.Field(i).Interface()
		switch tagName {
		case "L4_LOG_TAP_TYPES", "L7_LOG_STORE_TAP_TYPES", "DECAP_TYPE":
			if realValue, ok := configValue.(*string); ok {
				if realValue != nil {
					configValue, err = convertStrToIntList(*realValue)
					if err != nil {
						log.Error(err)
					}
				}
			}
		case "MAX_NPB_BPS", "MAX_TX_BANDWIDTH":
			if realValue, ok := configValue.(*int64); ok {
				if realValue != nil {
					configValue = *realValue / 1000000
				}
			}
		case "MAX_COLLECT_PPS":
			if realValue, ok := configValue.(*int); ok {
				if realValue != nil {
					configValue = *realValue / 1000
				}
			}
		case "DOMAINS":
			if realValue, ok := configValue.(*string); ok {
				if realValue != nil {
					tDomains := []string{}
					cDomains := strings.Split(*realValue, ",")
					for _, domain := range cDomains {
						if domain != "" {
							tDomains = append(tDomains, domain)
						}
					}
					configValue = tDomains
				}
			}
		}
		config.setValue(configValue)
	}
}

func (m *GroupConfigMananger) getLabels() []*ConfigLabel {
	return m.Labels
}

func (m *GroupConfigMananger) generateConfigMap() {
	configMap := make(map[string]*ConfigBase)
	for _, label := range m.Labels {
		for key, value := range label.Configs {
			configMap[key] = value
		}
	}
	m.configMap = configMap
}

func getNewConfigManager() *GroupConfigMananger {
	configManager := deepcopy.Copy(newConfigManager).(*GroupConfigMananger)
	configManager.generateConfigMap()
	return configManager
}

func getDetailConfigManager() *GroupConfigMananger {
	configManager := deepcopy.Copy(detailConfigManager).(*GroupConfigMananger)
	configManager.generateConfigMap()
	return configManager
}
