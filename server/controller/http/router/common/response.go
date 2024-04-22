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

package common

import (
	"net/http"

	"github.com/gin-gonic/gin"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
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

func StatusPartialContentResponse(c *gin.Context, data interface{}, optStatus string, description string) {
	c.JSON(http.StatusPartialContent, Response{
		OptStatus:   "PARTIAL_RESULT",
		Description: description,
		Data:        data,
	})
}

func JsonResponse(c *gin.Context, data interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *servicecommon.ServiceError:
			switch t.Status {
			case httpcommon.RESOURCE_NOT_FOUND, httpcommon.INVALID_POST_DATA, httpcommon.RESOURCE_NUM_EXCEEDED,
				httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED, httpcommon.RESOURCE_ALREADY_EXIST,
				httpcommon.PARAMETER_ILLEGAL, httpcommon.INVALID_PARAMETERS:
				BadRequestResponse(c, t.Status, t.Message)
			case httpcommon.SERVER_ERROR, httpcommon.CONFIG_PENDING:
				InternalErrorResponse(c, data, t.Status, t.Message)
			case httpcommon.SERVICE_UNAVAILABLE:
				ServiceUnavailableResponse(c, data, t.Status, t.Message)
			case httpcommon.STATUES_PARTIAL_CONTENT:
				StatusPartialContentResponse(c, data, t.Status, t.Message)
			}
		default:
			InternalErrorResponse(c, data, httpcommon.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, httpcommon.SUCCESS, "")
	}
}
