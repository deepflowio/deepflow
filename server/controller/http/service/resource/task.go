/**
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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/task"
)

func GetTask(id int) (map[string]interface{}, error) {
	isMaster, masterCtrlIP, httpPort, err := currentControllerIsMaster()
	if err != nil {
		return nil, err
	}

	var done int
	if isMaster {
		done = task.GetManager().CheckTaskDone(id)
	} else {
		jsonResp, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/tasks/%d/", masterCtrlIP, httpPort, id), nil)
		if err != nil {
			return nil, err
		}
		done = jsonResp.Get("DATA").Get("COMPLETED").MustInt()
	}
	return map[string]interface{}{"ID": id, "COMPLETED": done}, nil
}

func GetTasks() ([]task.Task, error) {
	isMaster, masterCtrlIP, httpPort, err := currentControllerIsMaster()
	if err != nil {
		return nil, err
	}

	var resp []task.Task
	if isMaster {
		resp = func(ts []*task.Task) []task.Task {
			result := make([]task.Task, len(ts))
			for _, t := range ts {
				result = append(result, *t)
			}
			return result
		}(task.GetManager().GetTasks())
	} else {
		jsonResp, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/tasks/", masterCtrlIP, httpPort), nil)
		if err != nil {
			return nil, err
		}
		b, err := jsonResp.Get("DATA").MarshalJSON()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(b, &resp)
	}
	return resp, err
}

func CreateTask(reqBody model.TaskCreate) (map[string]interface{}, error) {
	isMaster, masterCtrlIP, httpPort, err := currentControllerIsMaster()
	if err != nil {
		return nil, err
	}

	var id int
	if isMaster {
		id = task.GetManager().TryCreateTask(reqBody.ResourceType, &reqBody.URLInfo, &reqBody.UserInfo)
	} else {
		req := make(map[string]interface{})
		b, _ := json.Marshal(reqBody)
		json.Unmarshal(b, &req)
		jsonResp, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/tasks/", masterCtrlIP, httpPort), req)
		if err != nil {
			return nil, err
		}
		id = jsonResp.Get("DATA").Get("TASK_ID").MustInt()
	}

	return map[string]interface{}{"TASK_ID": id}, nil
}

func currentControllerIsMaster() (ok bool, masterCtrlIP string, httpPort int, err error) {
	curCtrlIP := common.GetNodeIP()
	masterCtrlIP, httpPort, _, err = common.GetMasterControllerHostPort()
	return curCtrlIP == masterCtrlIP, masterCtrlIP, httpPort, err
}
