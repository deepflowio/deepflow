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

package router

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type Mail struct{}

func NewMail() *Mail {
	return new(Mail)
}

func (m *Mail) RegisterTo(e *gin.Engine) {
	e.GET("/v1/mail-server/", getMailServer)
	e.POST("/v1/mail-server/", createMailServer)
	e.PATCH("/v1/mail-server/:lcuuid/", updateMailServer)
	e.DELETE("/v1/mail-server/:lcuuid/", deleteMailServer)
}

func getMailServer(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("lcuuid"); ok {
		args["lcuuid"] = value
	}
	data, err := service.GetMailServer(args)
	JsonResponse(c, data, err)
}

func createMailServer(c *gin.Context) {
	var err error
	var mailCreate model.MailServerCreate
	fmt.Println(c.Request.URL.Query())
	// 参数校验
	err = c.ShouldBindBodyWith(&mailCreate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}

	data, err := service.CreateMailServer(mailCreate)
	JsonResponse(c, data, err)
}

func updateMailServer(c *gin.Context) {
	var err error
	var mailServerUpdate model.MailServerUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&mailServerUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	data, err := service.UpdateMailServer(lcuuid, patchMap)
	JsonResponse(c, data, err)
}

func deleteMailServer(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteMailServer(lcuuid)
	JsonResponse(c, data, err)
}
