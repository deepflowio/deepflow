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
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/querier/common"
)

type Response struct {
	OptStatus   string      `json:"OPT_STATUS"`
	Description string      `json:"DESCRIPTION"`
	Result      interface{} `json:"result"`
	Debug       interface{} `json:"debug"`
}

func HttpResponse(c *gin.Context, httpCode int, data interface{}, debug interface{}, optStatus string, description string) {
	if debug != nil {
		c.JSON(httpCode, Response{
			OptStatus:   optStatus,
			Description: description,
			Result:      data,
			Debug:       debug,
		})
	} else {
		c.JSON(httpCode, Response{
			OptStatus:   optStatus,
			Description: description,
			Result:      data,
		})
	}
}

func BadRequestResponse(c *gin.Context, optStatus string, description string) {
	c.JSON(http.StatusBadRequest, Response{
		OptStatus:   optStatus,
		Description: description,
	})
}

func InternalErrorResponse(c *gin.Context, data interface{}, debug interface{}, optStatus string, description string) {
	c.JSON(http.StatusInternalServerError, Response{
		OptStatus:   optStatus,
		Description: description,
		Result:      data,
		Debug:       debug,
	})
}

func JsonResponse(c *gin.Context, data interface{}, debug interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *common.ServiceError:
			switch t.Status {
			case common.RESOURCE_NOT_FOUND, common.INVALID_POST_DATA, common.RESOURCE_NUM_EXCEEDED,
				common.SELECTED_RESOURCES_NUM_EXCEEDED:
				BadRequestResponse(c, t.Status, t.Message)
			case common.SERVER_ERROR:
				InternalErrorResponse(c, data, debug, t.Status, t.Message)
			}
		default:
			InternalErrorResponse(c, data, debug, common.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, debug, common.SUCCESS, "")
	}
}
