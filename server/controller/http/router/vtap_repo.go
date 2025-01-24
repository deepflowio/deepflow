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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type VtapRepo struct{}

func NewVtapRepo() *VtapRepo {
	return new(VtapRepo)
}

func (vr *VtapRepo) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtap-repo/", getVtapRepo)
	e.POST("/v1/vtap-repo/", createVtapRepo)
	e.DELETE("/v1/vtap-repo/", deleteVtapRepo)
}

func getVtapRepo(c *gin.Context) {
	data, err := service.GetVtapRepo(httpcommon.GetUserInfo(c).ORGID, nil)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func createVtapRepo(c *gin.Context) {
	vtapRepo := &metadbmodel.VTapRepo{
		Name:     c.PostForm("NAME"),
		Arch:     c.PostForm("ARCH"),
		Branch:   c.PostForm("BRANCH"),
		RevCount: c.PostForm("REV_COUNT"),
		CommitID: c.PostForm("COMMIT_ID"),
		OS:       c.PostForm("OS"),
		K8sImage: c.PostForm("K8S_IMAGE"),
	}

	// get binary file
	if len(vtapRepo.K8sImage) == 0 {
		file, fileHeader, err := c.Request.FormFile("IMAGE")
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		defer file.Close()

		vtapRepo.Image = make([]byte, fileHeader.Size)
		_, err = file.Read(vtapRepo.Image)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
	}

	data, err := service.CreateVtapRepo(httpcommon.GetUserInfo(c).ORGID, vtapRepo)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

type VTapRepoDelete struct {
	ImageName string `json:"image_name" binding:"required"`
}

func deleteVtapRepo(c *gin.Context) {
	vtapRepo := VTapRepoDelete{}
	err := c.BindJSON(&vtapRepo)
	orgID := httpcommon.GetUserInfo(c).ORGID
	if err != nil {
		log.Error(err, logger.NewORGPrefix(orgID))
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	response.JSON(c, response.SetError(service.DeleteVtapRepo(orgID, vtapRepo.ImageName)))
}
