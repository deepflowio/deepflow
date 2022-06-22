package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/monitor/config"
)

var vtapLicenseTypeAllocPriority = []int{
	common.VTAP_LICENSE_TYPE_DEDICATED,
	common.VTAP_LICENSE_TYPE_C,
	common.VTAP_LICENSE_TYPE_B,
	common.VTAP_LICENSE_TYPE_A,
}

var vtapTypeToSupportedLicenseTypes = map[int][]int{
	common.VTAP_TYPE_KVM:                  {common.VTAP_LICENSE_TYPE_A, common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_EXSI:                 {common.VTAP_LICENSE_TYPE_A, common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_HYPER_V:              {common.VTAP_LICENSE_TYPE_A, common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_TUNNEL_DECAPSULATION: {common.VTAP_LICENSE_TYPE_A},
	common.VTAP_TYPE_WORKLOAD_V:           {common.VTAP_LICENSE_TYPE_A, common.VTAP_LICENSE_TYPE_B, common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_WORKLOAD_P:           {common.VTAP_LICENSE_TYPE_A, common.VTAP_LICENSE_TYPE_B, common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_POD_HOST:             {common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_POD_VM:               {common.VTAP_LICENSE_TYPE_C},
	common.VTAP_TYPE_DEDICATED:            {common.VTAP_LICENSE_TYPE_DEDICATED},
}

type VTapLicenseAllocation struct {
	cfg config.MonitorConfig

	LicenseTotalCount [common.VTAP_LICENSE_TYPE_MAX]int // 各种类型的授权总数
	LicenseUsedCount  [common.VTAP_LICENSE_TYPE_MAX]int // 各种类型的已使用授权数

	// 以下字段用于检测license个数是否超出、license个数消耗
	vtapsAuthorizedByHostSharedLicense [common.VTAP_LICENSE_TYPE_MAX]map[int][]string // 消耗同一个授权(因为在同一个宿主机上)的采集器
	vtapsAuthorizedByExclusiveLicense  [common.VTAP_LICENSE_TYPE_MAX][]string         // 单独消耗授权的采集器

	vmIDToHostID      map[int]int // 虚拟机ID与宿主机ID的对应关系
	podNodeIDToHostID map[int]int // 容器节点ID与宿主机ID的对应关系
}

func NewVTapLicenseAllocation(cfg config.MonitorConfig) *VTapLicenseAllocation {
	vtapLicenseAllocation := VTapLicenseAllocation{}
	vtapLicenseAllocation.cfg = cfg
	for i := range [common.VTAP_LICENSE_TYPE_MAX]int{} {
		vtapLicenseAllocation.vtapsAuthorizedByHostSharedLicense[i] = make(map[int][]string)
		vtapLicenseAllocation.vtapsAuthorizedByExclusiveLicense[i] = make([]string, 0)
	}
	vtapLicenseAllocation.vmIDToHostID = make(map[int]int)
	vtapLicenseAllocation.podNodeIDToHostID = make(map[int]int)
	return &vtapLicenseAllocation
}

func (v *VTapLicenseAllocation) Start() {
	go func() {
		for range time.Tick(time.Duration(v.cfg.LicenseCheckInterval) * time.Second) {
			// 获取各类license总数
			licenseTotalCount, _, err := v.GetLicenseTotalCount()
			if err != nil {
				log.Error("get license total count failed")
				continue
			}
			v.LicenseTotalCount = licenseTotalCount

			// 获取相关资源管理关系
			v.vmIDToHostID, v.podNodeIDToHostID = v.GetResourceConnection()
			// 检查已经授权的采集器，是否授权依然有效
			v.checkLicense()
			// 为尚未授权的采集器分配授权
			v.allocLicenseType()

			// 中间变量清零
			for i := range [common.VTAP_LICENSE_TYPE_MAX]int{} {
				v.vtapsAuthorizedByHostSharedLicense[i] = make(map[int][]string)
				v.vtapsAuthorizedByExclusiveLicense[i] = make([]string, 0)
			}
		}
	}()
}

func (v *VTapLicenseAllocation) GetLicenseTotalCount() (
	[common.VTAP_LICENSE_TYPE_MAX]int, [common.VTAP_LICENSE_TYPE_MAX][common.VTAP_LICENSE_FUNCTION_MAX]int, error,
) {
	var licenseTotalCount [common.VTAP_LICENSE_TYPE_MAX]int
	var functionLicenseTotalCount [common.VTAP_LICENSE_TYPE_MAX][common.VTAP_LICENSE_FUNCTION_MAX]int

	// 调用warrant API获取license授权信息
	url := fmt.Sprintf("http://%s:%d/licensedata", v.cfg.Warrant.Host, v.cfg.Warrant.Port)
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		log.Errorf("call url (%s) get licensedata failed", url)
		return licenseTotalCount, functionLicenseTotalCount, err
	}

	licenseMap := response.Get("DATA").Get("LICENSE").MustMap()

	for licenseType, licenseTypeStr := range map[int]string{
		common.VTAP_LICENSE_TYPE_A:         "A_VTAP",
		common.VTAP_LICENSE_TYPE_B:         "B_VTAP",
		common.VTAP_LICENSE_TYPE_C:         "C_VTAP",
		common.VTAP_LICENSE_TYPE_DEDICATED: "DEDICATED_VTAP",
	} {
		licenseData, ok := licenseMap[licenseTypeStr]
		if !ok {
			errMsg := fmt.Sprintf("no %s data in warrant api", licenseTypeStr)
			log.Error(errMsg)
			return licenseTotalCount, functionLicenseTotalCount, errors.New(errMsg)
		}
		licenseDataMap := licenseData.(map[string]interface{})

		// 获取该类型采集器各功能授权个数
		functionTypeLicenseCounts := []int{}
		for _, functionTypeStr := range map[int]string{
			common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING: "APPLICATION_MONITORING",
			common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING:     "NETWORK_MONITORING",
			common.VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION:   "TRAFFIC_DISTRIBUTION",
		} {
			//TODO: 检查配置文件中是否配置了该功能授权，如果未配置，无需用于功能授权个数计算

			functionTypeCount, ok := licenseDataMap[functionTypeStr]
			if !ok {
				errMsg := fmt.Sprintf(
					"no %s %s data in warrant api", licenseTypeStr, functionTypeStr,
				)
				log.Error(errMsg)
				return licenseTotalCount, functionLicenseTotalCount, errors.New(errMsg)
			}
			functionTypeCountInt, _ := functionTypeCount.(json.Number).Int64()
			functionTypeLicenseCounts = append(
				functionTypeLicenseCounts, int(functionTypeCountInt),
			)
		}

		// 采集器的授权个数等于配置文件中功能授权个数的最小值
		sort.Ints(functionTypeLicenseCounts)
		licenseTotalCount[licenseType] = functionTypeLicenseCounts[0]
	}
	return licenseTotalCount, functionLicenseTotalCount, nil
}

func (v *VTapLicenseAllocation) GetResourceConnection() (map[int]int, map[int]int) {
	var podNodes []mysql.PodNode
	var vms []mysql.VM
	var hosts []mysql.Host
	var vmPodNodeConns []mysql.VMPodNodeConnection

	mysql.Db.Find(&podNodes)
	mysql.Db.Find(&vms)
	mysql.Db.Find(&hosts)
	mysql.Db.Find(&vmPodNodeConns)
	// 构造map，用于后续判断采集器对应的宿主机
	hostIPToHostID := make(map[string]int)
	for _, host := range hosts {
		hostIPToHostID[host.IP] = host.ID
	}

	vmIDToHostID := make(map[int]int)
	for _, vm := range vms {
		hostID, ok := hostIPToHostID[vm.LaunchServer]
		if !ok {
			continue
		}
		vmIDToHostID[vm.ID] = hostID
	}

	podNodeIDToHostID := make(map[int]int)
	for _, conn := range vmPodNodeConns {
		hostID, ok := v.vmIDToHostID[conn.VMID]
		if !ok {
			continue
		}
		podNodeIDToHostID[conn.PodNodeID] = hostID
	}

	return vmIDToHostID, podNodeIDToHostID
}

// 如果类型是KVM/EXSI/Hyper-V，launchServerID直接使用
// 如果类型是Workload-P/Workload-V，根据launchServerID查找HostID
// 如果类型是容器-P/容器-V，根据launchServerID查找HostID
// 如果类型是隧道解封装，launchServerID=0
func (v *VTapLicenseAllocation) GetVTapHostID(vtap mysql.VTap) int {
	launchServerID := vtap.LaunchServerID
	ok := true
	switch vtap.Type {
	case common.VTAP_TYPE_WORKLOAD_V, common.VTAP_TYPE_WORKLOAD_P:
		launchServerID, ok = v.vmIDToHostID[vtap.LaunchServerID]
		if !ok {
			launchServerID = 0
		}
	case common.VTAP_TYPE_POD_HOST, common.VTAP_TYPE_POD_VM:
		launchServerID, ok = v.podNodeIDToHostID[vtap.LaunchServerID]
		if !ok {
			launchServerID = 0
		}
	case common.VTAP_TYPE_TUNNEL_DECAPSULATION:
		launchServerID = 0
	}
	return launchServerID
}

// 检查采集器是否可使用当前授权类型
// 通过个数是否超出授权类型个数来检测
// - 检查launchServerID是否在vtapsAuthorizedByHostSharedLicense中
// - 如果存在，则认为已有同宿主机上的采集器消耗过授权，无需再次判断和消耗
//   - 将采集器加入vtapsAuthorizedByHostSharedLicense中
// - 如果不存在，则检查当前授权的采集器个数是否超出
//   - 如果超出，则进入下一优先级
//   - 如果不超出，则检查该采集器是否有对应的宿主机
//     - 如果有，则加入vtapsAuthorizedByHostSharedLicense
//     - 如果没有，则加入vtapsAuthorizedByExclusiveLicense
func (v *VTapLicenseAllocation) checkVTapLicense(
	vtap mysql.VTap, launchServerID, licenseType, licenseUsedCount int,
) error {
	if _, ok := v.vtapsAuthorizedByHostSharedLicense[licenseType][launchServerID]; ok {
		v.vtapsAuthorizedByHostSharedLicense[licenseType][launchServerID] = append(
			v.vtapsAuthorizedByHostSharedLicense[licenseType][launchServerID], vtap.Lcuuid,
		)
	} else {
		if licenseUsedCount >= v.LicenseTotalCount[licenseType] {
			errMsg := fmt.Sprintf(
				"no available license(%d) for vtap (%s)", licenseType, vtap.Name,
			)
			return errors.New(errMsg)
		}
		if launchServerID != 0 {
			v.vtapsAuthorizedByHostSharedLicense[licenseType][launchServerID] = append(
				v.vtapsAuthorizedByHostSharedLicense[licenseType][launchServerID], vtap.Lcuuid,
			)
		} else {
			v.vtapsAuthorizedByExclusiveLicense[licenseType] = append(
				v.vtapsAuthorizedByExclusiveLicense[licenseType], vtap.Lcuuid,
			)
		}
	}
	return nil
}

func (v *VTapLicenseAllocation) checkLicense() {
	var vtaps []mysql.VTap
	var licenseUsedCount [common.VTAP_LICENSE_TYPE_MAX]int

	log.Info("license check starting")

	// 查询已授权的采集器
	mysql.Db.Where("license_type IS NOT NULL").Find(&vtaps)
	// 遍历采集器，判断是否已经超出授权个数
	for _, vtap := range vtaps {
		// 授权检测
		licenseType := vtap.LicenseType
		launchServerID := v.GetVTapHostID(vtap)
		if err := v.checkVTapLicense(
			vtap, launchServerID, licenseType, licenseUsedCount[licenseType],
		); err != nil {
			log.Infof("no available license(%d) for vtap (%s)", licenseType, vtap.Name)
			exceptions := vtap.Exceptions | common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH
			mysql.Db.Model(vtap).Update("exceptions", exceptions)
			continue
		}
		// 已使用授权个数 + 1
		licenseUsedCount[licenseType] += 1

		// TODO: 如果license_functions字段为空/配置文件不一致，则使用配置文件内容更新数据库

		// 授权检测正常后，注意恢复错误码
		// TODO: 调研批量更新方法
		if vtap.Exceptions&common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH != 0 {
			log.Infof("available license(%d) for vtap (%s)", licenseType, vtap.Name)
			exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH
			mysql.Db.Model(vtap).Update("exceptions", exceptions)
		}
	}
	v.LicenseUsedCount = licenseUsedCount
	log.Info("license check complete")
}

func (v *VTapLicenseAllocation) allocLicenseType() {
	var vtaps []mysql.VTap

	log.Info("alloc license type starting")

	// 查询未授权的采集器
	mysql.Db.Where("license_type IS NULL").Find(&vtaps)

	// 遍历采集器，根据采集器支持的授权类型和授权类型优先级，确定各采集器的授权类型
	for _, vtap := range vtaps {

		launchServerID := v.GetVTapHostID(vtap)
		// 获取当前支持的授权类型
		supportLicenseTypes, _ := vtapTypeToSupportedLicenseTypes[vtap.Type]
		sort.Ints(supportLicenseTypes)

		// 检查当前优先级的授权类型与采集器支持的授权类型是否有交集
		// 如果没有，则判断下一优先级类型
		// 如果有，则检查该优先级类型的采集器授权个数是否超出
		// - 如果超出，则判断下一优先级类型
		// - 如果不超出，则更新采集器授权类型为当前类型
		vtapLicenseType := common.VTAP_LICENSE_TYPE_NONE
		for _, licenseType := range vtapLicenseTypeAllocPriority {
			index := sort.SearchInts(supportLicenseTypes, licenseType)
			if index >= len(supportLicenseTypes) || supportLicenseTypes[index] != licenseType {
				continue
			}
			if err := v.checkVTapLicense(
				vtap, launchServerID, licenseType, v.LicenseUsedCount[licenseType],
			); err == nil {
				vtapLicenseType = licenseType
				break
			}
		}
		// 如果成功分配到可用给的授权，则授权类型，清空授权不足的错误码
		// 如果没有分配到可用给的授权，则更新错误码为授权不足
		if vtapLicenseType != common.VTAP_LICENSE_TYPE_NONE {
			log.Infof("alloc license type (%d) for vtap (%s)", vtapLicenseType, vtap.Name)

			dbUpdateMap := make(map[string]interface{})
			if vtap.Exceptions&common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH != 0 {
				exceptions := vtap.Exceptions ^ common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH
				dbUpdateMap["exceptions"] = exceptions
			}
			dbUpdateMap["license_type"] = vtapLicenseType
			// TODO: 则使用配置文件的license_functions更新数据库
			mysql.Db.Model(vtap).Updates(dbUpdateMap)

			// 已使用授权个数 +1
			v.LicenseUsedCount[vtapLicenseType] += 1

		} else {
			log.Debugf("no available license for vtap (%s)", vtap.Name)
			exceptions := vtap.Exceptions | common.VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH
			mysql.Db.Model(vtap).Update("exceptions", exceptions)
		}
	}
	log.Info("alloc license type complete")
}
