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

package plugin

import (
	"errors"
	"fmt"
	"strings"

	simplejson "github.com/bitly/go-simplejson"
	lua "github.com/yuin/gopher-lua"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("cloud.kubernetes_gather.plugin")

func GeneratePodGroup(orgID int, db *gorm.DB, metaData *simplejson.Json) (string, string, error) {
	var plugins []metadbmodel.Plugin
	err := db.Where("type = ?", common.PLUGIN_TYPE_LUA).Find(&plugins).Error
	if err != nil {
		return "", "", err
	}

	if len(plugins) == 0 {
		return "", "", nil
	}

	// TODO: convert to lua script
	podGroupType, podGroupName := customSCIPodGroup(orgID, metaData)
	if podGroupType != "" && podGroupName != "" {
		return podGroupType, podGroupName, nil
	}

	L := lua.NewState()
	defer L.Close()
	for _, plugin := range plugins {
		if err := L.DoString(string(plugin.Image)); err != nil {
			return "", "", fmt.Errorf("lua script loading error: (%s)", err.Error())
		}
		metaBytes, err := metaData.MarshalJSON()
		if err != nil {
			return "", "", fmt.Errorf("metaData marshal error: (%s)", err.Error())
		}
		err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal("GetWorkloadTypeAndName"),
			NRet:    2,
			Protect: true,
		}, lua.LString(string(metaBytes)))
		if err != nil {
			return "", "", fmt.Errorf("lua script execution error: (%s)", err.Error())
		}
		loadType, ok := L.Get(-2).(lua.LString)
		if !ok {
			return "", "", errors.New("lua script get pod group type failed")
		}
		podGroupType = string(loadType)

		loadName, ok := L.Get(-1).(lua.LString)
		if !ok {
			return "", "", errors.New("lua script get pod group name failed")
		}
		podGroupName = string(loadName)

		if podGroupType != "" && podGroupName != "" {
			break
		}
	}
	return podGroupType, podGroupName, nil
}

func customSCIPodGroup(orgID int, metaData *simplejson.Json) (string, string) {
	providerType := strings.ToLower(
		metaData.Get("labels").Get("virtual-kubelet.io/provider-cluster-type").MustString(),
	)
	if providerType != "serverless" && providerType != "proprietary" {
		log.Debugf("abstract type (%s) not support", providerType, logger.NewORGPrefix(orgID))
		return "", ""
	}

	abstractPGType := metaData.Get("labels").Get("virtual-kubelet.io/provider-workload-type").MustString()
	if abstractPGType == "" {
		if _, ok := metaData.Get("labels").CheckGet("statefulset.kubernetes.io/pod-name"); ok {
			abstractPGType = "StatefulSet"
		} else {
			abstractPGType = "Deployment"
		}
	}

	resourceName := metaData.Get("labels").Get("virtual-kubelet.io/provider-resource-name").MustString()
	if resourceName == "" {
		log.Debug("sci pod not found provider-resource-name", logger.NewORGPrefix(orgID))
		return "", ""
	}
	abstractPGName := resourceName
	targetIndex := strings.LastIndex(resourceName, "-")
	if targetIndex != -1 {
		abstractPGName = resourceName[:targetIndex]
	}
	return abstractPGType, abstractPGName
}
