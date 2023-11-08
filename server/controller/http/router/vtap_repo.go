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

package router

import (
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type VtapRepo struct{}

func NewVtapRepo() *VtapRepo {
	return new(VtapRepo)
}

func (vr *VtapRepo) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtap-repo/", getVtapRepo)
	e.POST("/v1/vtap-repo/", createVtapRepo)
	e.DELETE("/v1/vtap-repo/:name/", deleteVtapRepo)
}

func getVtapRepo(c *gin.Context) {
	data, err := service.GetVtapRepo(nil)
	JsonResponse(c, data, err)
}

func createVtapRepo(c *gin.Context) {
	vtapRepo := &mysql.VTapRepo{
		Name:     c.PostForm("NAME"),
		Arch:     c.PostForm("ARCH"),
		Branch:   c.PostForm("BRANCH"),
		RevCount: c.PostForm("REV_COUNT"),
		CommitID: c.PostForm("COMMIT_ID"),
		OS:       c.PostForm("OS"),
		Image:    []byte{},
	}

	// get file
	file, _, err := c.Request.FormFile("IMAGE")
	if err != nil {
		JsonResponse(c, nil, err)
		return
	}
	defer file.Close()

	_, err = file.Read(vtapRepo.Image)
	if err != nil {
		JsonResponse(c, nil, err)
		return
	}

	data, err := service.CreateVtapRepo(vtapRepo)
	JsonResponse(c, data, err)
}

func deleteVtapRepo(c *gin.Context) {
	name := c.Param("name")
	JsonResponse(c, nil, service.DeleteVtapRepo(name))
}
