package service

import (
	"strconv"
	"strings"

	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/model"
	"server/controller/monitor"
)

func GetLicenseConsumption(v *monitor.VTapLicenseAllocation) (map[string]model.LicenseConsumption, error) {
	// 获取授权总数
	_, licenseTotalCount, err := v.GetLicenseTotalCount()
	if err != nil {
		return nil, NewError(common.SERVER_ERROR, err.Error())
	}

	// 构造返回结果
	response := make(map[string]model.LicenseConsumption)
	for licenseType, licenseTypeStr := range map[int]string{
		common.VTAP_LICENSE_TYPE_A:         "A_VTAP",
		common.VTAP_LICENSE_TYPE_B:         "B_VTAP",
		common.VTAP_LICENSE_TYPE_C:         "C_VTAP",
		common.VTAP_LICENSE_TYPE_DEDICATED: "DEDICATED_VTAP",
	} {
		for functionType, functionTypeStr := range map[int]string{
			common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING: "APPLICATION_MONITORING",
			common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING:     "NETWORK_MONITORING",
			common.VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION:   "TRAFFIC_DISTRIBUTION",
		} {
			key := licenseTypeStr + "_" + functionTypeStr
			licenseConsumption := model.LicenseConsumption{
				Total:           licenseTotalCount[licenseType][functionType],
				LicenseFunction: functionType,
				LicenseType:     licenseType,
			}
			licenseConsumption.Used = v.LicenseUsedCount[licenseType]
			licenseConsumption.Avaliable = licenseConsumption.Total - licenseConsumption.Used
			response[key] = licenseConsumption
		}
	}
	return response, nil
}

func GetVTapLicenseConsumption(v *monitor.VTapLicenseAllocation) ([]model.VTapLicenseConsumption, error) {
	var vtaps []mysql.VTap
	var response []model.VTapLicenseConsumption

	mysql.Db.Find(&vtaps)

	// 遍历采集器，构造返回结果
	hostIDToVTapLcuuids := make(map[int][]string)
	for _, vtap := range vtaps {
		vtapResponse := model.VTapLicenseConsumption{
			ID:          vtap.ID,
			Name:        vtap.Name,
			Lcuuid:      vtap.Lcuuid,
			Type:        vtap.Type,
			LicenseType: vtap.LicenseType,
		}

		licenseFunctionsStr := strings.Split(vtap.LicenseFunctions, ",")
		vtapResponse.LicenseFunctions = make([]int, len(licenseFunctionsStr))
		for i, licenseFunction := range licenseFunctionsStr {
			vtapResponse.LicenseFunctions[i], _ = strconv.Atoi(licenseFunction)
		}

		vtapHostID := v.GetVTapHostID(vtap)
		if vtapHostID == 0 {
			vtapResponse.LicenseUsedCount = 1
		} else {
			if _, ok := hostIDToVTapLcuuids[vtapHostID]; ok {
				vtapResponse.LicenseUsedCount = 0
			} else {
				vtapResponse.LicenseUsedCount = 1
			}
			hostIDToVTapLcuuids[vtapHostID] = append(hostIDToVTapLcuuids[vtapHostID], vtap.Lcuuid)
		}
		response = append(response, vtapResponse)
	}
	return response, nil
}
