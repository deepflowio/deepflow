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

package resource

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/go-redis/redis/v9"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

func GetProcesses(c *gin.Context, redisConfig *redis.Config) (responseData []model.Process, err error) {
	responseData, err = getProcesses()
	return
}

func getProcesses() ([]model.Process, error) {
	// get processes
	processes, err := query.FindInBatches[mysql.Process](mysql.Db.Unscoped().Order("created_at DESC"))
	if err != nil {
		return nil, err
	}
	processData, err := GetProcessData(processes)
	if err != nil {
		return nil, err
	}
	var resp []model.Process
	for _, process := range processes {

		var deletedAt string
		if process.DeletedAt.Valid {
			deletedAt = process.DeletedAt.Time.Format(common.GO_BIRTHDAY)
		}

		processResp := model.Process{
			ResourceType: processData[process.ID].ResourceType,
			ResourceName: processData[process.ID].ResourceName,
			Name:         process.Name,
			VTapName:     processData[process.ID].VTapName,
			GPID:         process.ID,
			GPName:       process.ProcessName,
			PID:          process.PID,
			ProcessName:  process.ProcessName,
			CommandLine:  process.CommandLine,
			UserName:     process.UserName,
			OSAPPTags:    process.OSAPPTags,
			ResourceID:   processData[process.ID].ResourceID,
			StartTime:    process.StartTime.Format(common.GO_BIRTHDAY),
			UpdateAt:     process.UpdatedAt.Format(common.GO_BIRTHDAY),
			DeletedAt:    deletedAt,
		}
		resp = append(resp, processResp)
	}

	return resp, nil
}

type ProcessData struct {
	ResourceType int
	ResourceName string
	ResourceID   int
	VTapName     string
}

func GetProcessData(processes []*mysql.Process) (map[int]ProcessData, error) {
	// store vtap info
	vtapIDs := mapset.NewSet[uint32]()
	for _, item := range processes {
		vtapIDs.Add(item.VTapID)
	}
	var vtaps []mysql.VTap
	if err := mysql.Db.Where("id IN (?)", vtapIDs.ToSlice()).Find(&vtaps).Error; err != nil {
		return nil, err
	}
	type vtapInfo struct {
		Name           string
		Type           int
		LaunchServerID int
	}
	vtapIDToInfo := make(map[int]vtapInfo, len(vtaps))
	vmLaunchServerIDs := mapset.NewSet[int]()
	podNodeLaunchServerIDs := mapset.NewSet[int]()
	for _, vtap := range vtaps {
		vtapIDToInfo[vtap.ID] = vtapInfo{
			Name:           vtap.Name,
			Type:           vtap.Type,
			LaunchServerID: vtap.LaunchServerID,
		}
		if utils.Find([]int{common.VTAP_TYPE_WORKLOAD_V, common.VTAP_TYPE_WORKLOAD_P}, vtap.Type) {
			vmLaunchServerIDs.Add(vtap.LaunchServerID)
		} else if utils.Find([]int{common.VTAP_TYPE_POD_HOST, common.VTAP_TYPE_POD_VM}, vtap.Type) {
			podNodeLaunchServerIDs.Add(vtap.LaunchServerID)
		}
	}

	// store vm info
	var vms []mysql.VM
	if err := mysql.Db.Where("id IN (?)", vmLaunchServerIDs.ToSlice()).Find(&vms).Error; err != nil {
		return nil, err
	}
	vmIDToName := make(map[int]string, len(vms))
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}

	// store pod node info
	var podNodes []mysql.PodNode
	if err := mysql.Db.Where("id IN (?)", podNodeLaunchServerIDs.ToSlice()).Find(&podNodes).Error; err != nil {
		return nil, err
	}
	podNodeIDToName := make(map[int]string, len(podNodes))
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	// store pod info
	var pods []mysql.Pod
	if err := mysql.Db.Find(&pods).Error; err != nil {
		return nil, err
	}
	podIDToName := make(map[int]string, len(pods))
	containerIDToPodID := make(map[string]int)
	for _, pod := range pods {
		podIDToName[pod.ID] = pod.Name
		var containerIDs []string
		if len(pod.ContainerIDs) > 0 {
			containerIDs = strings.Split(pod.ContainerIDs, ", ")
		}
		for _, id := range containerIDs {
			containerIDToPodID[id] = pod.ID
		}
	}

	resp := make(map[int]ProcessData, len(processes))
	for _, process := range processes {
		var deviceType, resourceID int
		var resourceName string

		pVTapID := int(process.VTapID)
		if podID, ok := containerIDToPodID[process.ContainerID]; ok {
			deviceType = common.VIF_DEVICE_TYPE_POD
			resourceName = podIDToName[podID]
			resourceID = podID
		} else {
			deviceType = common.VTAP_TYPE_TO_DEVICE_TYPE[vtapIDToInfo[pVTapID].Type]
			if deviceType == common.VIF_DEVICE_TYPE_VM {
				resourceName = vmIDToName[vtapIDToInfo[pVTapID].LaunchServerID]
			} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
				resourceName = podNodeIDToName[vtapIDToInfo[pVTapID].LaunchServerID]
			}
			resourceID = vtapIDToInfo[pVTapID].LaunchServerID
		}
		resp[process.ID] = ProcessData{
			ResourceType: deviceType,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			VTapName:     vtapIDToInfo[pVTapID].Name,
		}
	}
	return resp, nil
}

func getCache(c *gin.Context) ([]model.Process, error) {
	var responseData []model.Process
	key, err := GenerateRedisKey(c.Request.Header, c.Request.URL)
	if err != nil {
		log.Error(err)
		return responseData, err
	}
	strCache, err := redis.GetClient().ResourceAPI.Get(c, key).Result()
	if errors.Is(err, goredis.Nil) {
		return responseData, nil
	}
	if err != nil {
		log.Error(err)
		return responseData, err
	}
	err = json.Unmarshal([]byte(strCache), &responseData)
	if err != nil {
		log.Error(err)
		return responseData, err
	}
	return responseData, nil
}

func setCache(c *gin.Context, redisConfig *redis.Config, data []model.Process) error {
	key, err := GenerateRedisKey(c.Request.Header, c.Request.URL)
	if err != nil {
		log.Error(err)
		return err
	}
	strCache, err := json.Marshal(data)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = redis.GetClient().ResourceAPI.Set(c, key, strCache, time.Duration(redisConfig.ResourceAPIExpireInterval)*time.Second).Result()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
