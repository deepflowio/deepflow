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
	"encoding/json"
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
	Page        Page        `json:"PAGE"`
}

// String returns the string representation of the response when Data is a byte slice.
func (r Response) String() string {
	if r.Page.IsValid() {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s,"PAGE":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)), string(r.Page.Bytes()))
	} else {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)))
	}
}

// Bytes returns the byte slice representation of the response when Data is a byte slice.
func (r Response) Bytes() []byte {
	return []byte(r.String())
}

type Page struct {
	Index     int `json:"INDEX"`
	Size      int `json:"SIZE"`
	Total     int `json:"TOTAL"`
	TotalItem int `json:"TOTAL_ITEM"`
}

func (p Page) IsValid() bool {
	return p.Index > 0 && p.Size > 0
}

func (p Page) Bytes() []byte {
	bytes, _ := json.Marshal(p)
	return bytes
}

func (p Page) String() string {
	bytes, _ := json.Marshal(p)
	return string(bytes)
}

type ResponseOption func(resp *Response)

func WithPage(p Page) ResponseOption {
	return func(resp *Response) {
		resp.Page = p
	}
}

func WithDescription(description string) ResponseOption {
	return func(resp *Response) {
		resp.Description = description
	}
}

func HttpResponse(c *gin.Context, httpCode int, data interface{}, optStatus string, options ...ResponseOption) {
	resp := Response{
		OptStatus: optStatus,
		Data:      data,
	}
	for _, option := range options {
		option(&resp)
	}
	c.JSON(httpCode, resp)
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

// TODO refactor, use ResponseOption
func JsonResponse(c *gin.Context, data interface{}, err error, respOptions ...ResponseOption) {
	if _, ok := data.([]byte); ok {
		BytesResponse(c, data, err, respOptions...)
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
		HttpResponse(c, 200, data, httpcommon.SUCCESS, respOptions...)
	}
}

func BytesResponse(c *gin.Context, data interface{}, err error, respOptions ...ResponseOption) {
	resp := Response{Data: data}
	for _, opt := range respOptions {
		opt(&resp)
	}
	if err != nil {
		switch t := err.(type) {
		case *servicecommon.ServiceError:
			resp.OptStatus = t.Status
			resp.Description = t.Message
			switch t.Status {
			case httpcommon.NO_PERMISSIONS:
				c.Data(http.StatusForbidden, gin.MIMEJSON, resp.Bytes())
			case httpcommon.RESOURCE_NOT_FOUND, httpcommon.INVALID_POST_DATA, httpcommon.RESOURCE_NUM_EXCEEDED,
				httpcommon.SELECTED_RESOURCES_NUM_EXCEEDED, httpcommon.RESOURCE_ALREADY_EXIST,
				httpcommon.PARAMETER_ILLEGAL, httpcommon.INVALID_PARAMETERS:
				c.Data(http.StatusBadRequest, gin.MIMEJSON, resp.Bytes())
			case httpcommon.SERVER_ERROR, httpcommon.CONFIG_PENDING:
				c.Data(http.StatusInternalServerError, gin.MIMEJSON, resp.Bytes())
			case httpcommon.SERVICE_UNAVAILABLE:
				c.Data(http.StatusServiceUnavailable, gin.MIMEJSON, resp.Bytes())
			case httpcommon.STATUES_PARTIAL_CONTENT:
				c.Data(http.StatusPartialContent, gin.MIMEJSON, resp.Bytes())
			default:
				if errors.Is(err, httpcommon.ERR_NO_PERMISSIONS) {
					c.Data(http.StatusForbidden, gin.MIMEJSON, resp.Bytes())
					return
				}
				c.Data(http.StatusBadRequest, gin.MIMEJSON, resp.Bytes())
			}
		default:
			resp.OptStatus = httpcommon.FAIL
			resp.Description = err.Error()
			c.Data(http.StatusInternalServerError, gin.MIMEJSON, resp.Bytes())
		}
	} else {
		resp.OptStatus = httpcommon.SUCCESS
		c.Data(http.StatusOK, gin.MIMEJSON, resp.Bytes())
	}
}
