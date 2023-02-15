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

package common

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/common"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
)

type Response struct {
	OptStatus   string      `json:"OPT_STATUS"`
	Description string      `json:"DESCRIPTION"`
	Data        interface{} `json:"DATA"`
}

func HttpResponse(c *gin.Context, httpCode int, data interface{}, optStatus string, description string) {
	c.JSON(httpCode, Response{
		OptStatus:   optStatus,
		Description: description,
		Data:        data,
	})
}

func BadRequestResponse(c *gin.Context, optStatus string, description string) {
	c.JSON(http.StatusBadRequest, Response{
		OptStatus:   optStatus,
		Description: description,
	})
}

func InternalErrorResponse(c *gin.Context, data interface{}, optStatus string, description string) {
	c.JSON(http.StatusInternalServerError, Response{
		OptStatus:   optStatus,
		Description: description,
		Data:        data,
	})
}

func ServiceUnavailableResponse(c *gin.Context, data interface{}, optStatus string, description string) {
	c.JSON(http.StatusServiceUnavailable, Response{
		OptStatus:   optStatus,
		Description: description,
		Data:        data,
	})
}

func JsonResponse(c *gin.Context, data interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *servicecommon.ServiceError:
			switch t.Status {
			case common.RESOURCE_NOT_FOUND, common.INVALID_POST_DATA, common.RESOURCE_NUM_EXCEEDED,
				common.SELECTED_RESOURCES_NUM_EXCEEDED, common.RESOURCE_ALREADY_EXIST,
				common.PARAMETER_ILLEGAL, common.INVALID_PARAMETERS:
				BadRequestResponse(c, t.Status, t.Message)
			case common.SERVER_ERROR:
				InternalErrorResponse(c, data, t.Status, t.Message)
			case common.SERVICE_UNAVAILABLE:
				ServiceUnavailableResponse(c, data, t.Status, t.Message)
			}
		default:
			InternalErrorResponse(c, data, common.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, common.SUCCESS, "")
	}
}
