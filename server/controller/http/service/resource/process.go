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

package resource

import (
	"encoding/json"
	"errors"
	"time"

	goredis "github.com/go-redis/redis/v9"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/gin-gonic/gin"
)

func GetProcesses(c *gin.Context, redisConfig *redis.RedisConfig) (responseData []model.Process, err error) {
	responseData, err = getProcesses()
	return
}

func getProcesses() ([]model.Process, error) {
	// store vtap info
	var vtaps []mysql.VTap
	if err := mysql.Db.Find(&vtaps).Error; err != nil {
		return nil, err
	}
	type vtapInfo struct {
		Name           string
		Type           int
		LaunchServerID int
	}
	vtapIDToInfo := make(map[int]vtapInfo, len(vtaps))
	for _, vtap := range vtaps {
		vtapIDToInfo[vtap.ID] = vtapInfo{
			Name:           vtap.Name,
			Type:           vtap.Type,
			LaunchServerID: vtap.LaunchServerID,
		}
	}

	// store vm info
	var vms []mysql.VM
	if err := mysql.Db.Find(&vms).Error; err != nil {
		return nil, err
	}
	vmIDToName := make(map[int]string, len(vms))
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}

	// store pod node info
	var podNodes []mysql.PodNode
	if err := mysql.Db.Find(&podNodes).Error; err != nil {
		return nil, err
	}
	podNodeIDToName := make(map[int]string, len(podNodes))
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	// get processes
	var processes []mysql.Process
	if err := mysql.Db.Unscoped().Order("created_at DESC").Find(&processes).Error; err != nil {
		return nil, err
	}
	var resp []model.Process
	for _, process := range processes {
		var resourceName string
		deviceType := common.VTAP_TYPE_TO_DEVICE_TYPE[vtapIDToInfo[process.VTapID].Type]
		if deviceType == common.VIF_DEVICE_TYPE_VM {
			resourceName = vmIDToName[vtapIDToInfo[process.VTapID].LaunchServerID]
		} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
			resourceName = podNodeIDToName[vtapIDToInfo[process.VTapID].LaunchServerID]
		}

		var deletedAt string
		if process.DeletedAt.Valid {
			deletedAt = process.DeletedAt.Time.Format(common.GO_BIRTHDAY)
		}

		processResp := model.Process{
			ResourceType: deviceType,
			ResourceName: resourceName,
			Name:         process.Name,
			VTapName:     vtapIDToInfo[process.VTapID].Name,
			GPID:         process.ID,
			GPName:       process.ProcessName,
			PID:          process.PID,
			ProcessName:  process.ProcessName,
			CommandLine:  process.CommandLine,
			UserName:     process.UserName,
			OSAPPTags:    process.OSAPPTags,
			ResourceID:   vtapIDToInfo[process.VTapID].LaunchServerID,
			StartTime:    process.StartTime.Format(common.GO_BIRTHDAY),
			UpdateAt:     process.UpdatedAt.Format(common.GO_BIRTHDAY),
			DeletedAt:    deletedAt,
		}
		resp = append(resp, processResp)
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
	strCache, err := redis.RedisDB.ResourceAPI.Get(c, key).Result()
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

func setCache(c *gin.Context, redisConfig *redis.RedisConfig, data []model.Process) error {
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
	_, err = redis.RedisDB.ResourceAPI.Set(c, key, strCache, time.Duration(redisConfig.ResourceAPIExpireInterval)*time.Second).Result()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
