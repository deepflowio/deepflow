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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource"
)

type Task struct{}

func NewTask() *Task {
	return new(Task)
}

func (t *Task) RegisterTo(e *gin.Engine) {
	e.GET("/v1/tasks/", getTasks)
	e.GET("/v1/tasks/:id/", getTask)

	e.POST("/v1/tasks/", createTask) // used to control task id
}

func getTask(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	data, err := resource.GetTask(id)
	common.JsonResponse(c, data, err)
}

func getTasks(c *gin.Context) {
	data, err := resource.GetTasks()
	common.JsonResponse(c, data, err)
}

func createTask(c *gin.Context) {
	var body model.TaskCreate
	err := c.ShouldBindBodyWith(&body, binding.JSON)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
		return
	}
	data, err := resource.CreateTask(body)
	common.JsonResponse(c, data, err)
}
