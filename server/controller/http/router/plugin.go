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
	"bytes"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

type Plugin struct{}

func NewPlugin() *Plugin {
	return new(Plugin)
}

func (p *Plugin) RegisterTo(e *gin.Engine) {
	e.GET("/v1/plugin/", getPlugin)
	e.POST("/v1/plugin/", createPlugin)
	e.DELETE("/v1/plugin/:name/", deletePlugin)
}

func getPlugin(c *gin.Context) {
	dbInfo, err := metadb.GetDB(httpcommon.GetUserInfo(c).ORGID)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	data, err := service.GetPlugin(dbInfo, nil)

	response.JSON(c, response.SetData(data), response.SetError(err))
}

func createPlugin(c *gin.Context) {
	t, err := strconv.Atoi(c.PostForm("TYPE"))
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	u, err := strconv.Atoi(c.PostForm("USER"))
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	plugin := &metadbmodel.Plugin{
		Name:     c.PostForm("NAME"),
		Type:     t,
		UserName: u,
	}

	// get file
	file, _, err := c.Request.FormFile("IMAGE")
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	defer file.Close()
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, file)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	plugin.Image = buf.Bytes()

	dbInfo, err := metadb.GetDB(httpcommon.GetUserInfo(c).ORGID)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	data, err := service.CreatePlugin(dbInfo, plugin)
	if err == nil {
		refresh.RefreshCache(dbInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	}
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func deletePlugin(c *gin.Context) {
	dbInfo, err := metadb.GetDB(httpcommon.GetUserInfo(c).ORGID)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}

	name := c.Param("name")
	if err = service.DeletePlugin(dbInfo, name); err == nil {
		refresh.RefreshCache(dbInfo.ORGID, []common.DataChanged{common.DATA_CHANGED_VTAP})
	}
	response.JSON(c, response.SetError(err))
}
