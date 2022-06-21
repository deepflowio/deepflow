package model

import (
	"time"
)

type ControllerUpdate struct {
	VtapMax int      `json:"VTAP_MAX" binding:"min=0,max=10000"`
	Region  string   `json:"REGION"`
	Azs     []string `json:"AZS"`
	IsAllAz bool     `json:"IS_ALL_AZ"`
	State   int      `json:"STATE"`
	NatIP   string   `json:"NAT_IP"`
}

type ControllerAz struct {
	Az     string `json:"AZ"`
	AzName string `json:"AZ_NAME"`
}

type Controller struct {
	ID                 int            `json:"ID"`
	IP                 string         `json:"IP"`
	Name               string         `json:"NAME"`
	NodeType           int            `json:"NODE_TYPE"`
	State              int            `json:"STATE"`
	NatIP              string         `json:"NAT_IP"`
	NatIPEnabled       int            `json:"NAT_IP_ENABLED"`
	CPUNum             int            `json:"CPU_NUM"`
	MemorySize         int64          `json:"MEMORY_SIZE"`
	Arch               string         `json:"ARCH"`
	ArchType           int            `json:"ARCH_TYPE"`
	Os                 string         `json:"OS"`
	OsType             int            `json:"OS_TYPE"`
	KernelVersion      string         `json:"KERNEL_VERSION"`
	VtapCount          int            `json:"VTAP_COUNT"`
	VTapMax            int            `json:"VTAP_MAX"`
	RegionDomainPrefix string         `json:"REGION_DOMAIN_PREFIX"`
	SyncedAt           time.Time      `json:"SYNCED_AT"`
	Region             string         `json:"REGION"`
	RegionName         string         `json:"REGION_NAME"`
	IsAllAz            bool           `json:"IS_ALL_AZ"`
	Azs                []ControllerAz `json:"AZS"`
	Lcuuid             string         `json:"LCUUID"`
}

type AnalyzerUpdate struct {
	VtapMax int      `json:"VTAP_MAX" binding:"min=0,max=10000"`
	Region  string   `json:"REGION"`
	Azs     []string `json:"AZS"`
	IsAllAz bool     `json:"IS_ALL_AZ"`
	State   int      `json:"STATE"`
	NatIP   string   `json:"NAT_IP"`
	Agg     int      `json:"AGG"`
}

type AnalyzerAz struct {
	Az     string `json:"AZ"`
	AzName string `json:"AZ_NAME"`
}

type Analyzer struct {
	ID                int          `json:"ID"`
	IP                string       `json:"IP"`
	Name              string       `json:"NAME"`
	State             int          `json:"STATE"`
	NatIP             string       `json:"NAT_IP"`
	NatIPEnabled      int          `json:"NAT_IP_ENABLED"`
	Agg               int          `json:"AGG"`
	CPUNum            int          `json:"CPU_NUM"`
	MemorySize        int64        `json:"MEMORY_SIZE"`
	Arch              string       `json:"ARCH"`
	ArchType          int          `json:"ARCH_TYPE"`
	Os                string       `json:"OS"`
	OsType            int          `json:"OS_TYPE"`
	KernelVersion     string       `json:"KERNEL_VERSION"`
	VtapCount         int          `json:"VTAP_COUNT"`
	VTapMax           int          `json:"VTAP_MAX"`
	PcapDataMountPath string       `json:"PCAP_DATA_MOUNT_PATH"`
	SyncedAt          time.Time    `json:"SYNCED_AT"`
	Region            string       `json:"REGION"`
	RegionName        string       `json:"REGION_NAME"`
	IsAllAz           bool         `json:"IS_ALL_AZ"`
	Azs               []AnalyzerAz `json:"AZS"`
	Lcuuid            string       `json:"LCUUID"`
}

type VtapUpdate struct {
	Lcuuid           string `json:"LCUUID"`
	Enable           int    `json:"ENABLE"`
	State            int    `json:"STATE"`
	VtapGroupLcuuid  string `json:"VTAP_GROUP_LCUUID"`
	LicenseType      int    `json:"LICENSE_TYPE"`
	LicenseFunctions []int  `json:"LICENSE_FUNCTIONS"`
}

type Vtap struct {
	ID                 int     `json:"ID"`
	Name               string  `json:"NAME"`
	State              int     `json:"STATE"`
	Enable             int     `json:"ENABLE"`
	LaunchServer       string  `json:"LAUNCH_SERVER"`
	LaunchServerID     int     `json:"LAUNCH_SERVER_ID"`
	Type               int     `json:"TYPE"`
	CtrlIP             string  `json:"CTRL_IP"`
	CtrlMac            string  `json:"CTRL_MAC"`
	ControllerIP       string  `json:"CONTROLLER_IP"`
	AnalyzerIP         string  `json:"ANALYZER_IP"`
	CurControllerIP    string  `json:"CUR_CONTROLLER_IP"`
	CurAnalyzerIP      string  `json:"CUR_ANALYZER_IP"`
	SyncedControllerAt string  `json:"SYNCED_CONTROLLER_AT"`
	SyncedAnalyzerAt   string  `json:"SYNCED_ANALYZER_AT"`
	BootTime           int     `json:"BOOT_TIME"`
	Revision           string  `json:"REVISION"`
	CompleteRevision   string  `json:"COMPLETE_REVISION"`
	Exceptions         []int64 `json:"EXCEPTIONS"`
	VtapGroupLcuuid    string  `json:"VTAP_GROUP_LCUUID"`
	VtapGroupName      string  `json:"VTAP_GROUP_NAME"`
	Az                 string  `json:"AZ"`
	AzName             string  `json:"AZ_NAME"`
	Region             string  `json:"REGION"`
	RegionName         string  `json:"REGION_NAME"`
	CPUNum             int     `json:"CPU_NUM"`
	MemorySize         int64   `json:"MEMORY_SIZE"`
	Arch               string  `json:"ARCH"`
	ArchType           int     `json:"ARCH_TYPE"`
	Os                 string  `json:"OS"`
	OsType             int     `json:"OS_TYPE"`
	KernelVersion      string  `json:"KERNEL_VERSION"`
	LicenseType        int     `json:"LICENSE_TYPE"`
	LicenseFunctions   []int   `json:"LICENSE_FUNCTIONS"`
	Lcuuid             string  `json:"LCUUID"`
	// TODO: format_state
	// TODO: format_type
	// TODO: format_exceptions
}

type HostVTapRebalanceResult struct {
	IP            string `json:"IP"`
	AZ            string `json:"AZ"`
	State         int    `json:"STATE"`
	BeforeVTapNum int    `json:"BEFORE_VTAP_NUM"`
	AfterVTapNum  int    `json:"AFTER_VTAP_NUM"`
	SwitchVTapNum int    `json:"SWITCH_VTAP_NUM"`
}

type AZVTapRebalanceResult struct {
	TotalSwitchVTapNum int                       `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []HostVTapRebalanceResult `json:"DETAILS"`
}

type VTapRebalanceResult struct {
	TotalSwitchVTapNum int                     `json:"TOTAL_SWITCH_VTAP_NUM"`
	Details            []AZVTapRebalanceResult `json:"DETAILS"`
}

type VtapGroup struct {
	ID                 int      `json:"ID"`
	Name               string   `json:"NAME"`
	UpdatedAt          string   `json:"UPDATED_AT"`
	ShortUUID          string   `json:"SHORT_UUID"`
	Lcuuid             string   `json:"LCUUID"`
	VtapLcuuids        []string `json:"VTAP_LCUUIDS"`
	DisableVtapLcuuids []string `json:"DISABLE_VTAP_LCUUIDS"`
	PendingVtapLcuuids []string `json:"PENDING_VTAP_LCUUIDS"`
}

type VtapGroupCreate struct {
	Name        string   `json:"NAME"`
	State       int      `json:"STATE"`
	Enable      int      `json:"ENABLE"`
	VtapLcuuids []string `json:"VTAP_LCUUIDS"`
}

type VtapGroupUpdate struct {
	Name        string   `json:"NAME"`
	State       int      `json:"STATE"`
	Enable      int      `json:"ENABLE"`
	VtapLcuuids []string `json:"VTAP_LCUUIDS"`
}

type DataSource struct {
	ID                        int    `json:"ID"`
	Name                      string `json:"NAME"`
	TsdbType                  string `json:"TSDB_TYPE"`
	State                     int    `json:"STATE"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID`
	BaseDataSourceName        string `json:"BASE_DATA_SOURCE_NAME`
	Interval                  int    `json:"INTERVAL"`
	RetentionTime             int    `json:"RETENTION_TIME"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR"`
	IsDefault                 bool   `json:"IS_DEFAULT"`
	UpdatedAt                 string `json:"UPDATED_AT"`
	Lcuuid                    string `json:"LCUUID"`
}

type DataSourceCreate struct {
	Name                      string `json:"NAME" binding:"required,min=1,max=10"`
	TsdbType                  string `json:"TSDB_TYPE" binding:"required,oneof=flow app"`
	BaseDataSourceID          int    `json:"BASE_DATA_SOURCE_ID" binding:"required"`
	Interval                  int    `json:"INTERVAL" binding:"required"`
	RetentionTime             int    `json:"RETENTION_TIME" binding:"required,min=1"`
	SummableMetricsOperator   string `json:"SUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Sum Max Min"`
	UnSummableMetricsOperator string `json:"UNSUMMABLE_METRICS_OPERATOR" binding:"required,oneof=Avg Max Min"`
}

type DataSourceUpdate struct {
	RetentionTime int `json:"RETENTION_TIME" binding:"required,min=1"`
}

type LicenseConsumption struct {
	LicenseType     int `json:"LICENSE_TYPE"`
	LicenseFunction int `json:"LICENSE_FUNCTION"`

	Total     int `json:"TOTAL"`
	Avaliable int `json:"AVALIABLE"`
	Used      int `json:"CONSUMPTION"`
}

type VTapLicenseConsumption struct {
	ID               int    `json:"ID"`
	Name             string `json:"NAME"`
	Type             int    `json:"TYPE"`
	LicenseType      int    `json:"LICENSE_TYPE"`
	LicenseFunctions []int  `json:"LICENSE_FUNCTIONS"`
	Lcuuid           string `json:"LCUUID"`

	LicenseUsedCount int `json:"LICENSE_CONSUME"`
}

type Domain struct {
	ID             int                    `json:"ID"`
	Name           string                 `json:"NAME"`
	DisplayName    string                 `json:"DISPLAY_NAME"`
	ClusterID      string                 `json:"CLUSTER_ID"`
	Type           int                    `json:"TYPE"`
	Enabled        int                    `json:"ENABLED"`
	State          int                    `json:"STATE"`
	ErrorMsg       string                 `json:"ERROR_MSG"`
	ControllerIP   string                 `json:"CONTROLLER_IP"`
	ControllerName string                 `json:"CONTROLLER_NAME"`
	VTapName       string                 `json:"VTAP_NAME"`
	VTapCtrlIP     string                 `json:"VTAP_CTRL_IP"`
	VTapCtrlMAC    string                 `json:"VTAP_CTRL_MAC"`
	IconID         int                    `json:"ICON_ID"`
	K8sEnabled     int                    `json:"K8S_ENABLED"`
	Config         map[string]interface{} `json:"CONFIG"`
	AZCount        int                    `json:"AZ_COUNT"`
	RegionCount    int                    `json:"REGION_COUNT"`
	PodClusters    []string               `json:"POD_CLUSTERS"`
	CreatedAt      string                 `json:"CREATED_AT"`
	SyncedAt       string                 `json:"SYNCED_AT"`
	Lcuuid         string                 `json:"LCUUID"`
}

type DomainCreate struct {
	Name         string                 `json:"NAME" binding:"required"`
	Type         int                    `json:"TYPE" binding:"required"`
	IconID       int                    `json:"ICON_ID"`       // TODO: 修改为required
	ControllerIP string                 `json:"CONTROLLER_IP"` // TODO: 修改为required
	Config       map[string]interface{} `json:"CONFIG" binding:"required"`
}

type DomainUpdate struct {
	Name         string                 `json:"NAME"`
	Enabled      int                    `json:"ENABLED"`
	IconID       int                    `json:"ICON_ID"`
	ControllerIP string                 `json:"CONTROLLER_IP"`
	Config       map[string]interface{} `json:"CONFIG"`
}

type SubDomain struct {
	ID           int                    `json:"ID"`
	Name         string                 `json:"NAME"`
	DisplayName  string                 `json:"DISPLAY_NAME"`
	ClusterID    string                 `json:"CLUSTER_ID"`
	State        int                    `json:"STATE"`
	ErrorMsg     string                 `json:"ERROR_MSG"`
	VPCName      string                 `json:"EPC_NAME"`
	Domain       string                 `json:"DOMAIN"`
	Config       map[string]interface{} `json:"CONFIG"`
	CreateMethod int                    `json:"CREATE_METHOD"`
	CreatedAt    string                 `json:"CREATED_AT"`
	SyncedAt     string                 `json:"SYNCED_AT"`
	Lcuuid       string                 `json:"LCUUID"`
}

type SubDomainCreate struct {
	Name   string                 `json:"NAME" binding:"required"`
	Config map[string]interface{} `json:"CONFIG" binding:"required"`
	Domain string                 `json:"DOMAIN" binding:"required"`
}

type SubDomainUpdate struct {
	Config map[string]interface{} `json:"CONFIG"`
}
