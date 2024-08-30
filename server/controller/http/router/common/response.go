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

package common

import (
	"errors"
	"fmt"
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

func StatusForbiddenResponse(c *gin.Context, description string) {
	c.JSON(http.StatusForbidden, Response{
		OptStatus:   httpcommon.NO_PERMISSIONS,
		Description: description,
	})
}

func JsonResponse(c *gin.Context, data interface{}, err error) {
	if _, ok := data.([]byte); ok {
		bytesResponse(c, data, err)
		return
	}

	if err != nil {
		switch t := err.(type) {
		case *servicecommon.ServiceError:
			switch t.Status {
			case httpcommon.NO_PERMISSIONS:
				StatusForbiddenResponse(c, t.Message)
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
			if errors.Is(err, httpcommon.ERR_NO_PERMISSIONS) {
				StatusForbiddenResponse(c, err.Error())
				return
			}
			InternalErrorResponse(c, data, httpcommon.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, httpcommon.SUCCESS, "")
	}
}

func bytesResponse(c *gin.Context, data interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *servicecommon.ServiceError:
			switch t.Status {
			case httpcommon.NO_PERMISSIONS:
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusForbidden, gin.MIMEJSON, []byte(d))
			case httpcommon.RESOURCE_NOT_FOUND, httpcommon.INVALID_POST_DATA, httpcommon.RESOURCE_NUM_EXCEEDED,
				httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED, httpcommon.RESOURCE_ALREADY_EXIST,
				httpcommon.PARAMETER_ILLEGAL, httpcommon.INVALID_PARAMETERS:
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusBadRequest, gin.MIMEJSON, []byte(d))
			case httpcommon.SERVER_ERROR, httpcommon.CONFIG_PENDING:
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusInternalServerError, gin.MIMEJSON, []byte(d))
			case httpcommon.SERVICE_UNAVAILABLE:
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusServiceUnavailable, gin.MIMEJSON, []byte(d))
			case httpcommon.STATUES_PARTIAL_CONTENT:
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusPartialContent, gin.MIMEJSON, []byte(d))
			default:
				if errors.Is(err, httpcommon.ERR_NO_PERMISSIONS) {
					d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
					c.Data(http.StatusForbidden, gin.MIMEJSON, []byte(d))
					return
				}
				d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, t.Status, t.Message, string(data.([]byte)))
				c.Data(http.StatusBadRequest, gin.MIMEJSON, []byte(d))
			}
		default:
			d := fmt.Sprintf(`{"OPT_STATUS":%s,"DESCRIPTION":%s,"DATA":%s}`, httpcommon.FAIL, err.Error(), string(data.([]byte)))
			c.Data(http.StatusInternalServerError, gin.MIMEJSON, []byte(d))
		}
	} else {
		d := fmt.Sprintf(`{"OPT_STATUS":"SUCCESS","DESCRIPTION":"","DATA": %v}`, string(data.([]byte)))
		c.Data(http.StatusOK, gin.MIMEJSON, []byte(d))
	}
}
