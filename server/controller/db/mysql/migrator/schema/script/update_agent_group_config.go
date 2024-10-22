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

package script

import (
	"strings"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/agent_config"
)

// associate sql issu 6.6.1.13
const SCRIPT_UPDATE_AGENT_GROUP_CONFIG = "6.6.1.13"

func ScriptUpdateAgentGroupConfigurations(db *gorm.DB) error {
	log.Infof("execute script (%s)", SCRIPT_UPDATE_VM_PODNS_TAG)
	err := updateVMCloudTags(db)
	if err != nil {
		return err
	}

	err = updatePodNamespaceCloudTags(db)
	if err != nil {
		return err
	}

	return nil
}

func convertToDb(sData *agent_config.AgentGroupConfig, tData *agent_config.AgentGroupConfigModel) {
	ignoreName := []string{"ID", "YamlConfig", "Lcuuid", "VTapGroupLcuuid", "VTapGroupID",
		"L4LogTapTypes", "L4LogIgnoreTapSides", "L7LogIgnoreTapSides",
		"L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps", "MaxNpbBps", "MaxTxBandwidth",
		"WasmPlugins", "SoPlugins",
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
