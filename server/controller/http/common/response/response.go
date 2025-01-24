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

package response

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

// ResponseSetter is a function that sets a response field.
type ResponseSetter func(resp *Response)

// SetError sets the error in the response.
func SetError(err error) ResponseSetter {
	return func(resp *Response) {
		resp.err = err
	}
}

// SetPage sets the page in the response.
func SetPage(p Page) ResponseSetter {
	return func(resp *Response) {
		resp.Page = p
	}
}

// SetDescription sets the description in the response.
func SetDescription(description string) ResponseSetter {
	return func(resp *Response) {
		resp.Description = description
	}
}

// SetStatus sets the status in the response.
func SetStatus(status string) ResponseSetter {
	return func(resp *Response) {
		resp.OptStatus = status
	}
}

// SetData sets the data in the response.
func SetData(data interface{}) ResponseSetter {
	return func(resp *Response) {
		resp.Data = data
	}
}

// SetHttpStatus sets the http status in the response.
func SetHttpStatus(httpStatus int) ResponseSetter {
	return func(resp *Response) {
		resp.HttpStatus = httpStatus
	}
}

type Response struct {
	rawPageResponse

	err        error `json:"-"` // Error is not serializ`ed
	HttpStatus int   `json:"-"` // httpStatus is not serialized
}

type rawPageResponse struct {
	rawResponse
	Page Page `json:"PAGE"`
}

type rawResponse struct {
	OptStatus   string      `json:"OPT_STATUS"`
	Description string      `json:"DESCRIPTION"`
	Data        interface{} `json:"DATA"`
}

func NewResponse(options ...ResponseSetter) Response {
	resp := Response{}
	for _, option := range options {
		option(&resp)
	}
	resp.Format()
	return resp
}

func (r *Response) Format() {
	if r.err != nil {
		switch t := r.err.(type) {
		case *serviceError:
			r.OptStatus = t.Status
			r.Description = t.Message
		default:
			r.OptStatus = httpcommon.FAIL
			r.Description = r.err.Error()
		}
	} else {
		r.OptStatus = httpcommon.SUCCESS
	}
	if r.HttpStatus == 0 {
		r.HttpStatus = httpcommon.OptStatusToHTTPStatus[r.OptStatus]
	}
}

func (r Response) JSON() interface{} {
	if r.Page.IsValid() {
		return r.rawPageResponse
	}
	return r.rawResponse
}

// String returns the string representation of the response when Data is a byte slice.
func (r Response) JsonString() string {
	if r.Page.IsValid() {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s,"PAGE":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)), string(r.Page.Bytes()))
	} else {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)))
	}
}

// Bytes returns the byte slice representation of the response when Data is a byte slice.
func (r Response) JSONBytes() []byte {
	return []byte(r.JsonString())
}

func (r Response) CSVBytes() []byte {
	return r.Data.([]byte)
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

// JSON writes a JSON response to the client.
func JSON(c *gin.Context, options ...ResponseSetter) {
	resp := NewResponse(options...)

	if _, ok := resp.Data.([]byte); ok {
		c.Data(resp.HttpStatus, gin.MIMEJSON, resp.JSONBytes())
		return
	}

	c.JSON(resp.HttpStatus, resp.JSON())
}

// CSV writes a CSV file to the response. You should set []byte as the data in the response.
func CSV(c *gin.Context, fileName string, options ...ResponseSetter) {
	resp := NewResponse(options...)

	c.Header(common.HEADER_KEY_CONTENT_TYPE, common.CONTENT_TYPE_CSV)
	c.Header(common.HEADER_KEY_CONTENT_DISPOSITION, fmt.Sprintf(common.CONTENT_DISPOSITION_ATTACHMENT_FILENAME, fileName+".csv"))
	c.Writer.Write(resp.CSVBytes())
}
