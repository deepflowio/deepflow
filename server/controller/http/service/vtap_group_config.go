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

package service

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

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

func ConvertStrToIntListWithIgnore(convertStr string, ignoreFields []int) ([]int, error) {
	if len(convertStr) == 0 {
		return []int{}, nil
	}
	splitStr := strings.Split(convertStr, ",")
	var result []int
	for _, src := range splitStr {
		target, err := strconv.Atoi(src)
		if err != nil {
			return []int{}, err
		}
		if common.Contains[int](ignoreFields, target) {
			continue
		}
		result = append(result, target)
	}

	return result, nil
}

func convertIntSliceToString(intSlice []int) string {
	strSlice := make([]string, 0, len(intSlice))
	for _, ci := range intSlice {
		strSlice = append(strSlice, strconv.Itoa(ci))
	}

	return strings.Join(strSlice, ",")
}

func copyStruct(from, to interface{}, ignoreName []string) {
	fromValue := reflect.ValueOf(from)
	toValue := reflect.ValueOf(to)
	if fromValue.Kind() != reflect.Ptr || toValue.Kind() != reflect.Ptr {
		return
	}
	if fromValue.IsNil() || toValue.IsNil() {
		return
	}
	fromElem := fromValue.Elem()
	toElem := toValue.Elem()
	for i := 0; i < toElem.NumField(); i++ {
		toField := toElem.Type().Field(i)
		if common.Contains(ignoreName, toField.Name) {
			// set value to avoid return nil
			if toField.Type.Kind() == reflect.Slice {
				sliceType := reflect.SliceOf(toField.Type.Elem())
				emptySlice := reflect.MakeSlice(sliceType, 0, 0)
				toElem.Field(i).Set(emptySlice)
			}
			continue
		}
		fromFieldName, ok := fromElem.Type().FieldByName(toField.Name)
		if ok && fromFieldName.Type == toField.Type {
			toElem.Field(i).Set(fromElem.FieldByName(toField.Name))
		}
	}
}

var DecapTypeData = map[int]string{
	0: "无",
	1: "VXLAN",
	2: "IPIP",
	3: "GRE",
}

func getTypeInfo(tapTypeValue int, idToTapTypeName map[int]string) *model.TypeInfo {
	var typeInfo *model.TypeInfo
	switch tapTypeValue {
	case 0:
		typeInfo = &model.TypeInfo{
			ID:   tapTypeValue,
			Name: "全部",
		}
	case -1:
		typeInfo = &model.TypeInfo{
			ID:   tapTypeValue,
			Name: "无",
		}
	default:
		name := idToTapTypeName[tapTypeValue]
		typeInfo = &model.TypeInfo{
			ID:   tapTypeValue,
			Name: name,
		}
	}
	return typeInfo
}

// tapSideIDToName references feild l4_log_ignore_tap_sides of file agent_group_config_example.yaml.
var tapSideIDToName = map[int]string{
	0:  "其他网卡",      // Rest
	1:  "客户端网卡",     // Client
	2:  "服务端网卡",     // Server
	4:  "本机网卡",      // Local
	9:  "客户端容器节点",   // ClientNode
	10: "服务端容器节点",   // ServerNode
	17: "客户端宿主机",    // ClientHypervisor
	18: "服务端宿主机",    // ServerHypervisor
	25: "客户端到网关宿主机", // ClientGatewayHypervisor
	26: "网关宿主机到服务端", // ServerGatewayHypervisor
	33: "客户端到网关",    // ClientGateway
	34: "网关到服务端",    // ServerGateway
	41: "客户端进程",     // ClientProcess
	42: "服务端进程",     // ServerProcess
	// 48: "应用",        // App
	// 49: "客户端应用",     // ClientApp
	// 50: "服务端应用",     // ServerApp
}

var DeprecatedTapSideID = []int{48, 49, 50}

func convertDBToJson(
	sData *mysql.VTapGroupConfiguration,
	tData *model.VTapGroupConfigurationResponse,
	idToTapTypeName map[int]string,
	lcuuidToDomain map[string]string) {

	ignoreName := []string{"ID", "YamlConfig", "L4LogTapTypes", "L4LogIgnoreTapSides",
		"L7LogIgnoreTapSides", "L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps",
		"MaxNpbBps", "MaxTxBandwidth", "WasmPlugins", "SoPlugins"}
	copyStruct(sData, tData, ignoreName)
	if sData.L4LogTapTypes != nil {
		cL4LogTapTypes, err := ConvertStrToIntList(*sData.L4LogTapTypes)
		if err == nil {
			for _, tapTypeValue := range cL4LogTapTypes {
				tData.L4LogTapTypes = append(tData.L4LogTapTypes,
					getTypeInfo(tapTypeValue, idToTapTypeName))
			}
		} else {
			log.Error(err)
		}
	}
	if sData.L4LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*sData.L4LogIgnoreTapSides, DeprecatedTapSideID)
		if err != nil {
			log.Error(err)
		} else {
			for _, tapSideValue := range tapSides {
				if name, ok := tapSideIDToName[tapSideValue]; ok {
					tData.L4LogIgnoreTapSides = append(tData.L4LogIgnoreTapSides,
						&model.TapSideInfo{
							ID:   tapSideValue,
							Name: name,
						})
				}
			}
		}
	}
	if sData.L7LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*sData.L7LogIgnoreTapSides, DeprecatedTapSideID)
		if err == nil {
			for _, tapSideValue := range tapSides {
				if name, ok := tapSideIDToName[tapSideValue]; ok {
					tData.L7LogIgnoreTapSides = append(tData.L7LogIgnoreTapSides,
						&model.TapSideInfo{
							ID:   tapSideValue,
							Name: name,
						})
				}

			}
		} else {
			log.Error(err)
		}
	}
	if sData.L7LogStoreTapTypes != nil {
		cL7LogStoreTapTypes, err := ConvertStrToIntList(*sData.L7LogStoreTapTypes)
		if err == nil {
			for _, tapTypeValue := range cL7LogStoreTapTypes {
				tData.L7LogStoreTapTypes = append(tData.L7LogStoreTapTypes,
					getTypeInfo(tapTypeValue, idToTapTypeName))
			}
		} else {
			log.Error(err)
		}
	}
	if sData.DecapType != nil {
		cDecapType, err := ConvertStrToIntList(*sData.DecapType)
		if err == nil {
			for _, decapType := range cDecapType {
				typeInfo := &model.TypeInfo{
					ID:   decapType,
					Name: DecapTypeData[decapType],
				}

				tData.DecapType = append(tData.DecapType, typeInfo)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.Domains != nil {
		cDomains := strings.Split(*sData.Domains, ",")
		for _, domain := range cDomains {
			var domainInfo *model.DomainInfo
			if domain == "0" {
				domainInfo = &model.DomainInfo{
					ID:   domain,
					Name: "全部",
				}
			}
			if domainInfo == nil && domain != "" {
				domainInfo = &model.DomainInfo{
					ID:   domain,
					Name: lcuuidToDomain[domain],
				}
			}
			if domainInfo != nil {
				tData.Domains = append(tData.Domains, domainInfo)
			}
		}
	}
	if sData.MaxCollectPps != nil {
		cMaxCollectPps := *sData.MaxCollectPps / 1000
		tData.MaxCollectPps = &cMaxCollectPps
	}
	if sData.MaxNpbBps != nil {
		cMaxNpbBps := *sData.MaxNpbBps / 1000000
		tData.MaxNpbBps = &cMaxNpbBps
	}
	if sData.MaxTxBandwidth != nil {
		cMaxTxBandwidth := *sData.MaxTxBandwidth / 1000000
		tData.MaxTxBandwidth = &cMaxTxBandwidth
	}

	if sData.WasmPlugins != nil && len(*sData.WasmPlugins) > 0 {
		cWasmPlugins := strings.Split(*sData.WasmPlugins, ",")
		for _, wasmPlugin := range cWasmPlugins {
			tData.WasmPlugins = append(tData.WasmPlugins, wasmPlugin)
		}
	}
	if sData.SoPlugins != nil && len(*sData.SoPlugins) > 0 {
		cSoPlugins := strings.Split(*sData.SoPlugins, ",")
		for _, soPlugin := range cSoPlugins {
			tData.SoPlugins = append(tData.SoPlugins, soPlugin)
		}
	}
}

func convertDBToYaml(sData *mysql.VTapGroupConfiguration, tData *model.VTapGroupConfiguration) {
	ignoreName := []string{"ID", "VTapGroupLcuuid", "VTapGroupID", "Lcuuid", "YamlConfig",
		"L4LogTapTypes", "L4LogIgnoreTapSides", "L7LogIgnoreTapSides",
		"L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps", "MaxNpbBps", "MaxTxBandwidth",
		"PrometheusHttpAPIAddresses", "WasmPlugins", "SoPlugins",
	}
	copyStruct(sData, tData, ignoreName)
	if sData.YamlConfig != nil {
		yamlConfig := &model.StaticConfig{}
		if err := yaml.Unmarshal([]byte(*sData.YamlConfig), yamlConfig); err == nil {
			tData.YamlConfig = yamlConfig
		} else {
			log.Error(err)
		}
	}

	if sData.L4LogTapTypes != nil {
		cL4LogTapTypes, err := ConvertStrToIntList(*sData.L4LogTapTypes)
		if err == nil {
			for _, tapTypeValue := range cL4LogTapTypes {
				tData.L4LogTapTypes = append(tData.L4LogTapTypes, tapTypeValue)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.L4LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*sData.L4LogIgnoreTapSides, DeprecatedTapSideID)
		if err == nil {
			for _, tapSide := range tapSides {
				tData.L4LogIgnoreTapSides = append(tData.L4LogIgnoreTapSides, tapSide)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.L7LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*sData.L7LogIgnoreTapSides, DeprecatedTapSideID)
		if err == nil {
			for _, tapSide := range tapSides {
				tData.L7LogIgnoreTapSides = append(tData.L7LogIgnoreTapSides, tapSide)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.L7LogStoreTapTypes != nil {
		cL7LogStoreTapTypes, err := ConvertStrToIntList(*sData.L7LogStoreTapTypes)
		if err == nil {
			for _, tapTypeValue := range cL7LogStoreTapTypes {
				tData.L7LogStoreTapTypes = append(tData.L7LogStoreTapTypes, tapTypeValue)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.DecapType != nil {
		cDecapType, err := ConvertStrToIntList(*sData.DecapType)
		if err == nil {
			for _, decapType := range cDecapType {
				tData.DecapType = append(tData.DecapType, decapType)
			}
		} else {
			log.Error(err)
		}
	}
	if sData.Domains != nil {
		cDomains := strings.Split(*sData.Domains, ",")
		for _, domain := range cDomains {
			if domain != "" {
				tData.Domains = append(tData.Domains, domain)
			}
		}
	}
	if sData.PrometheusHttpAPIAddresses != nil {
		tData.PrometheusHttpAPIAddresses = strings.Split(*sData.PrometheusHttpAPIAddresses, ",")
	}
	if sData.MaxCollectPps != nil {
		cMaxCollectPps := *sData.MaxCollectPps / 1000
		tData.MaxCollectPps = &cMaxCollectPps
	}
	if sData.MaxNpbBps != nil {
		cMaxNpbBps := *sData.MaxNpbBps / 1000000
		tData.MaxNpbBps = &cMaxNpbBps
	}
	if sData.MaxTxBandwidth != nil {
		cMaxTxBandwidth := *sData.MaxTxBandwidth / 1000000
		tData.MaxTxBandwidth = &cMaxTxBandwidth
	}

	if sData.WasmPlugins != nil {
		cWasmPlugins := strings.Split(*sData.WasmPlugins, ",")
		for _, wasmPlugin := range cWasmPlugins {
			if wasmPlugin != "" {
				tData.WasmPlugins = append(tData.WasmPlugins, wasmPlugin)
			}
		}
	}
	if sData.SoPlugins != nil {
		cSoPlugins := strings.Split(*sData.SoPlugins, ",")
		for _, soPlugin := range cSoPlugins {
			if soPlugin != "" {
				tData.SoPlugins = append(tData.SoPlugins, soPlugin)
			}
		}
	}
}

func convertJsonToDb(sData *model.VTapGroupConfiguration, tData *mysql.VTapGroupConfiguration) {
	convertToDb(sData, tData)
}

func convertYamlToDb(sData *model.VTapGroupConfiguration, tData *mysql.VTapGroupConfiguration) {
	if sData.YamlConfig != nil {
		b, err := yaml.Marshal(sData.YamlConfig)
		if err == nil {
			dbYamlConfig := string(b)
			tData.YamlConfig = &dbYamlConfig
		} else {
			log.Error(err)
		}
	} else {
		tData.YamlConfig = nil
	}

	convertToDb(sData, tData)
}

func convertToDb(sData *model.VTapGroupConfiguration, tData *mysql.VTapGroupConfiguration) {
	ignoreName := []string{"ID", "YamlConfig", "Lcuuid", "VTapGroupLcuuid", "VTapGroupID",
		"L4LogTapTypes", "L4LogIgnoreTapSides", "L7LogIgnoreTapSides",
		"L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps", "MaxNpbBps", "MaxTxBandwidth",
		"PrometheusHttpAPIAddresses", "WasmPlugins", "SoPlugins",
	}
	copyStruct(sData, tData, ignoreName)
	if len(sData.L4LogTapTypes) > 0 {
		cL4LogTapTypes := convertIntSliceToString(sData.L4LogTapTypes)
		tData.L4LogTapTypes = &cL4LogTapTypes
	} else {
		tData.L4LogTapTypes = nil
	}
	if len(sData.L4LogIgnoreTapSides) > 0 {
		tapSides := convertIntSliceToString(sData.L4LogIgnoreTapSides)
		tData.L4LogIgnoreTapSides = &tapSides
	} else {
		tData.L4LogIgnoreTapSides = nil
	}
	if len(sData.L7LogIgnoreTapSides) > 0 {
		tapSides := convertIntSliceToString(sData.L7LogIgnoreTapSides)
		tData.L7LogIgnoreTapSides = &tapSides
	} else {
		tData.L7LogIgnoreTapSides = nil
	}
	if len(sData.L7LogStoreTapTypes) > 0 {
		cL7LogStoreTapTypes := convertIntSliceToString(sData.L7LogStoreTapTypes)
		tData.L7LogStoreTapTypes = &cL7LogStoreTapTypes
	} else {
		tData.L7LogStoreTapTypes = nil
	}
	if len(sData.DecapType) > 0 {
		cDecapType := convertIntSliceToString(sData.DecapType)
		tData.DecapType = &cDecapType
	} else {
		tData.DecapType = nil
	}
	if len(sData.Domains) > 0 {
		cDomains := strings.Join(sData.Domains, ",")
		tData.Domains = &cDomains
	} else {
		tData.Domains = nil
	}
	if len(sData.PrometheusHttpAPIAddresses) > 0 {
		cAddrs := strings.Join(sData.PrometheusHttpAPIAddresses, ",")
		tData.PrometheusHttpAPIAddresses = &cAddrs
	} else {
		tData.PrometheusHttpAPIAddresses = nil
	}
	if sData.MaxCollectPps != nil {
		cMaxCollectPps := *sData.MaxCollectPps * 1000
		tData.MaxCollectPps = &cMaxCollectPps
	} else {
		tData.MaxCollectPps = nil
	}
	if sData.MaxNpbBps != nil {
		cMaxNpbBps := *sData.MaxNpbBps * 1000000
		tData.MaxNpbBps = &cMaxNpbBps
	} else {
		tData.MaxNpbBps = nil
	}
	if sData.MaxTxBandwidth != nil {
		cMaxTxBandwidth := *sData.MaxTxBandwidth * 1000000
		tData.MaxTxBandwidth = &cMaxTxBandwidth
	} else {
		tData.MaxTxBandwidth = nil
	}
	if len(sData.WasmPlugins) > 0 {
		cWasmPlugins := strings.Join(sData.WasmPlugins, ",")
		tData.WasmPlugins = &cWasmPlugins
	} else {
		tData.WasmPlugins = nil
	}
	if len(sData.SoPlugins) > 0 {
		cSoPlugins := strings.Join(sData.SoPlugins, ",")
		tData.SoPlugins = &cSoPlugins
	} else {
		tData.SoPlugins = nil
	}
}

func CreateVTapGroupConfig(createData *model.VTapGroupConfiguration) (*mysql.VTapGroupConfiguration, error) {
	if createData.VTapGroupLcuuid == nil {
		return nil, fmt.Errorf("vtap_group_lcuuid is emty")
	}
	vTapGroupLcuuid := *createData.VTapGroupLcuuid
	dbConfig := &mysql.VTapGroupConfiguration{}
	db := mysql.Db
	ret := db.Where("vtap_group_lcuuid = ?", vTapGroupLcuuid).First(dbConfig)
	if ret.Error == nil {
		return nil, fmt.Errorf("vtapgroup %s configuration already exist", vTapGroupLcuuid)
	}

	dbGroup := &mysql.VTapGroup{}
	ret = db.Where("lcuuid = ?", vTapGroupLcuuid).First(dbGroup)
	if ret.Error != nil {
		return nil, fmt.Errorf("vtapgroup (%s) not found", vTapGroupLcuuid)
	}
	dbData := &mysql.VTapGroupConfiguration{}
	convertJsonToDb(createData, dbData)
	dbData.VTapGroupLcuuid = createData.VTapGroupLcuuid
	lcuuid := uuid.New().String()
	dbData.Lcuuid = &lcuuid
	mysql.Db.Create(dbData)
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return dbData, nil
}

func DeleteVTapGroupConfig(lcuuid string) (*mysql.VTapGroupConfiguration, error) {
	if lcuuid == "" {
		return nil, fmt.Errorf("lcuuid is None")
	}

	db := mysql.Db
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret := db.Where("lcuuid = ?", lcuuid).First(dbConfig)
	if ret.Error != nil {
		return nil, fmt.Errorf("vtap group configuration(%s) not found", lcuuid)
	}
	db.Delete(dbConfig)
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return dbConfig, nil
}

func UpdateVTapGroupConfig(lcuuid string, updateData *model.VTapGroupConfiguration) (*mysql.VTapGroupConfiguration, error) {
	if lcuuid == "" {
		return nil, fmt.Errorf("lcuuid is None")
	}

	db := mysql.Db
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret := db.Where("lcuuid = ?", lcuuid).First(dbConfig)
	if ret.Error != nil {
		return nil, fmt.Errorf("vtap group configuration(%s) not found", lcuuid)
	}
	convertJsonToDb(updateData, dbConfig)
	ret = db.Save(dbConfig)
	if ret.Error != nil {
		return nil, fmt.Errorf("save config failed, %s", ret.Error)
	}
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return dbConfig, nil
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

func getRealVTapGroupConfig(config *mysql.VTapGroupConfiguration) *mysql.VTapGroupConfiguration {
	ignoreName := []string{"ID", "VTapGroupLcuuid", "Lcuuid"}
	typeOfDefaultConfig := reflect.ValueOf(common.DefaultVTapGroupConfig).Elem()
	tt := reflect.TypeOf(config).Elem()
	tv := reflect.ValueOf(config).Elem()
	realConfiguration := &mysql.VTapGroupConfiguration{}
	typeOfRealConfiguration := reflect.ValueOf(realConfiguration).Elem()
	for i := 0; i < tv.NumField(); i++ {
		field := tt.Field(i)
		if common.Contains(ignoreName, field.Name) == true {
			typeOfRealConfiguration.Field(i).Set(tv.Field(i))
		}
		value := tv.Field(i)
		defaultValue := typeOfDefaultConfig.Field(i)
		if isBlank(value) == false {
			typeOfRealConfiguration.Field(i).Set(value)
		} else {
			typeOfRealConfiguration.Field(i).Set(defaultValue)
		}
	}

	return realConfiguration
}

func GetVTapGroupConfigs(filter map[string]interface{}) ([]*model.VTapGroupConfigurationResponse, error) {
	var dbConfigs []*mysql.VTapGroupConfiguration
	var tapTypes []*mysql.TapType
	var domains []*mysql.Domain
	var vtapGroups []*mysql.VTapGroup
	idToTapTypeName := make(map[int]string)
	lcuuidToDomain := make(map[string]string)
	lcuuidToVTapGroup := make(map[string]*mysql.VTapGroup)
	db := mysql.Db
	mysql.Db.Find(&dbConfigs)
	mysql.Db.Find(&tapTypes)
	mysql.Db.Find(&domains)
	if _, ok := filter["vtap_group_id"]; ok {
		mysql.Db.Where("short_uuid = ?", filter["vtap_group_id"]).Find(&vtapGroups)
	} else {
		db.Find(&vtapGroups)
	}
	for _, tapType := range tapTypes {
		idToTapTypeName[tapType.Value] = tapType.Name
	}
	for _, domain := range domains {
		lcuuidToDomain[domain.Lcuuid] = domain.Name
	}
	for i, vtapGroup := range vtapGroups {
		lcuuidToVTapGroup[vtapGroup.Lcuuid] = vtapGroups[i]
	}
	result := make([]*model.VTapGroupConfigurationResponse, 0, len(dbConfigs))
	for _, config := range dbConfigs {
		if config.VTapGroupLcuuid == nil || *config.VTapGroupLcuuid == "" {
			continue
		}
		vtapGroup, ok := lcuuidToVTapGroup[*config.VTapGroupLcuuid]
		if !ok {
			continue
		}
		realConfig := getRealVTapGroupConfig(config)
		mData := &model.VTapGroupConfigurationResponse{}
		mData.VTapGroupID = &vtapGroup.ShortUUID
		mData.VTapGroupName = &vtapGroup.Name
		convertDBToJson(realConfig, mData, idToTapTypeName, lcuuidToDomain)
		result = append(result, mData)
	}

	return result, nil
}

func GetVTapGroupDetailedConfig(lcuuid string) (*model.DetailedConfig, error) {
	if lcuuid == "" {
		return nil, fmt.Errorf("lcuuid is None")
	}
	db := mysql.Db
	realConfig := &mysql.VTapGroupConfiguration{}
	ret := db.Where("lcuuid = ?", lcuuid).First(realConfig)
	if ret.Error != nil {
		ret = db.Where("vtap_group_lcuuid = ?", lcuuid).First(realConfig)
		if ret.Error != nil {
			log.Errorf("vtap group configuration(%s) not found", lcuuid)
			realConfig = &mysql.VTapGroupConfiguration{}
		}
	}
	var tapTypes []*mysql.TapType
	var domains []*mysql.Domain
	idToTapTypeName := make(map[int]string)
	lcuuidToDomain := make(map[string]string)
	db.Find(&tapTypes)
	db.Find(&domains)
	for _, tapType := range tapTypes {
		idToTapTypeName[tapType.Value] = tapType.Name
	}
	for _, domain := range domains {
		lcuuidToDomain[domain.Lcuuid] = domain.Name
	}
	realData := &model.VTapGroupConfigurationResponse{}
	convertDBToJson(realConfig, realData, idToTapTypeName, lcuuidToDomain)
	defaultData := &model.VTapGroupConfigurationResponse{}
	convertDBToJson(common.DefaultVTapGroupConfig, defaultData, idToTapTypeName, lcuuidToDomain)
	response := &model.DetailedConfig{
		RealConfig:    realData,
		DefaultConfig: defaultData,
	}

	return response, nil
}

var emptyData = []byte{123, 125, 10}

func GetVTapGroupAdvancedConfig(lcuuid string) (string, error) {
	if lcuuid == "" {
		return "", fmt.Errorf("lcuuid is None")
	}
	db := mysql.Db
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret := db.Where("lcuuid = ?", lcuuid).First(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group configuration(%s) not found", lcuuid)
	}
	response := &model.VTapGroupConfiguration{}
	convertDBToYaml(dbConfig, response)
	b, err := yaml.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	if string(b) == string(emptyData) {
		b = nil
	}
	return string(b), nil
}

func GetVTapGroupAdvancedConfigs() ([]string, error) {
	var dbConfigs []mysql.VTapGroupConfiguration
	var dbGroups []mysql.VTapGroup
	lcuuidToShortUUID := make(map[string]string)
	db := mysql.Db
	db.Find(&dbGroups)
	for _, dbGroup := range dbGroups {
		lcuuidToShortUUID[dbGroup.Lcuuid] = dbGroup.ShortUUID
	}
	db.Find(&dbConfigs)
	result := make([]string, 0, len(dbConfigs))
	for _, dbConfig := range dbConfigs {
		if dbConfig.VTapGroupLcuuid == nil || *dbConfig.VTapGroupLcuuid == "" {
			continue
		}
		response := &model.VTapGroupConfiguration{}
		convertDBToYaml(&dbConfig, response)
		shortUUID := lcuuidToShortUUID[*dbConfig.VTapGroupLcuuid]
		response.VTapGroupID = &shortUUID
		b, err := yaml.Marshal(response)
		if err != nil {
			log.Error(err)
			continue
		}
		result = append(result, string(b))
	}
	return result, nil
}

func UpdateVTapGroupAdvancedConfig(lcuuid string, updateData *model.VTapGroupConfiguration) (string, error) {
	db := mysql.Db
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret := db.Where("lcuuid = ?", lcuuid).First(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group configuration(%s) not found", lcuuid)
	}
	convertYamlToDb(updateData, dbConfig)
	ret = db.Save(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("save config failed, %s", ret.Error)
	}
	response := &model.VTapGroupConfiguration{}
	convertDBToYaml(dbConfig, response)
	b, err := yaml.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	if string(b) == string(emptyData) {
		b = nil
	}
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return string(b), nil
}

func CreateVTapGroupAdvancedConfig(createData *model.VTapGroupConfiguration) (string, error) {
	if createData.VTapGroupID == nil {
		return "", fmt.Errorf("vtap_group_id is None")
	}
	shortUUID := createData.VTapGroupID
	db := mysql.Db
	vtapGroup := &mysql.VTapGroup{}
	ret := db.Where("short_uuid = ?", shortUUID).First(vtapGroup)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) not found", *shortUUID)
	}
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret = db.Where("vtap_group_lcuuid = ?", vtapGroup.Lcuuid).First(dbConfig)
	if ret.Error == nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) configuration already exist", *shortUUID)
	}
	convertYamlToDb(createData, dbConfig)
	dbConfig.VTapGroupLcuuid = &vtapGroup.Lcuuid
	lcuuid := uuid.New().String()
	dbConfig.Lcuuid = &lcuuid
	ret = db.Save(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("save config failed, %s", ret.Error)
	}
	response := &model.VTapGroupConfiguration{}
	convertDBToYaml(dbConfig, response)
	response.VTapGroupID = shortUUID
	b, err := yaml.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return string(b), nil
}

func GetVTapGroupConfigByFilter(args map[string]string) (string, error) {
	shortUUID := args["vtap_group_id"]
	if shortUUID == "" {
		return "", fmt.Errorf("short uuid is None")
	}
	db := mysql.Db
	vtapGroup := &mysql.VTapGroup{}
	ret := db.Where("short_uuid = ?", shortUUID).First(vtapGroup)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) not found", shortUUID)
	}
	dbConfig := &mysql.VTapGroupConfiguration{}
	ret = db.Where("vtap_group_lcuuid = ?", vtapGroup.Lcuuid).First(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) configuration not found", shortUUID)
	}
	response := &model.VTapGroupConfiguration{}
	convertDBToYaml(dbConfig, response)
	response.VTapGroupID = &shortUUID
	b, err := yaml.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	return string(b), nil
}

func DeleteVTapGroupConfigByFilter(args map[string]string) (string, error) {
	shortUUID := args["vtap_group_id"]
	if shortUUID == "" {
		return "", fmt.Errorf("short uuid is None")
	}
	db := mysql.Db
	vtapGroup := &mysql.VTapGroup{}
	ret := db.Where("short_uuid = ?", shortUUID).First(vtapGroup)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) not found", shortUUID)
	}

	dbConfig := &mysql.VTapGroupConfiguration{}
	ret = db.Where("vtap_group_lcuuid = ?", vtapGroup.Lcuuid).First(dbConfig)
	if ret.Error != nil {
		return "", fmt.Errorf("vtap group(short_uuid=%s) configuration not found", shortUUID)
	}
	db.Delete(dbConfig)
	response := &model.VTapGroupConfiguration{}
	convertDBToYaml(dbConfig, response)
	response.VTapGroupID = &shortUUID
	b, err := yaml.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_VTAP})
	return string(b), nil
}

func GetVTapGroupExampleConfig() (string, error) {
	return string(model.YamlAgentGroupConfig), nil
}
