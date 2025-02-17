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
	"math"

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

// SetOptStatus sets the status in the response.
func SetOptStatus(status string) ResponseSetter {
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

// SetHTTPStatus sets the http status in the response.
func SetHTTPStatus(httpStatus int) ResponseSetter {
	return func(resp *Response) {
		resp.HttpStatus = httpStatus
	}
}

type Response struct {
	RawPageResponse

	err        error `json:"-"` // Error is not serializ`ed
	HttpStatus int   `json:"-"` // httpStatus is not serialized
}

type RawPageResponse struct {
	RawResponse
	Page Page `json:"PAGE"`
}

type RawResponse struct {
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
			if r.OptStatus == "" {
				r.OptStatus = httpcommon.FAIL
			}
			r.Description = r.err.Error()
		}
	}
	if r.OptStatus == "" {
		r.OptStatus = httpcommon.SUCCESS
	}
	if r.HttpStatus == 0 {
		r.HttpStatus = httpcommon.OptStatusToHTTPStatus[r.OptStatus]
	}
}

func (r Response) JSON() interface{} {
	if r.Page.IsValid() {
		return r.RawPageResponse
	}
	return r.RawResponse
}

// JSONString returns the string representation of the response when Data is a byte slice.
func (r Response) JSONString() string {
	if r.Page.IsValid() {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s,"PAGE":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)), string(r.Page.Bytes()))
	} else {
		return fmt.Sprintf(`{"OPT_STATUS":"%s","DESCRIPTION":"%s","DATA":%s}`, r.OptStatus, r.Description, string(r.Data.([]byte)))
	}
}

// JSONBytes returns the byte slice representation of the response when Data is a byte slice.
func (r Response) JSONBytes() []byte {
	return []byte(r.JSONString())
}

func (r Response) CSVBytes() []byte {
	return r.Data.([]byte)
}

type Page struct {
	Index     int `json:"INDEX"`
	Size      int `json:"SIZE"`
	Total     int `json:"TOTAL"`      // total count of page
	TotalItem int `json:"TOTAL_ITEM"` // total count of data
}

func NewPage(index, size int) *Page {
	return &Page{
		Index: index,
		Size:  size,
	}
}

func (p *Page) Fill(dataLength int) (start, end int) {
	if dataLength == 0 {
		return 0, 0
	}
	p.Total = int(math.Ceil(float64(dataLength) / float64(p.Size)))
	p.TotalItem = dataLength
	if !p.IsValid() {
		return 0, 0
	}
	if p.Index > p.Total {
		p.Index = p.Total
	}

	start = (p.Index - 1) * p.Size
	end = start + p.Size
	if end > dataLength {
		end = dataLength
	}
	return
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

// DownloadCSV writes a DownloadCSV file to the response. You should set []byte as the data in the response.
func DownloadCSV(c *gin.Context, fileName string, opts ...ResponseSetter) {
	resp := NewResponse(opts...)
	resp.HttpStatus = httpcommon.OptStatusToHTTPStatus[resp.OptStatus]

	c.Writer.WriteHeader(resp.HttpStatus)
	c.Header(common.HEADER_KEY_CONTENT_TYPE, common.CONTENT_TYPE_CSV)
	c.Header(common.HEADER_KEY_CONTENT_DISPOSITION, fmt.Sprintf(common.CONTENT_DISPOSITION_ATTACHMENT_FILENAME, fileName))
	c.Header("Transfer-Encoding", "chunked")
	data := resp.Data.([]byte)
	chunkSize := 100 * 1024
	for len(data) > 0 {
		end := chunkSize
		if len(data) < chunkSize {
			end = len(data)
		}
		n, err := c.Writer.Write(data[:end])
		if err != nil {
			JSON(c, SetError(err))
			return
		}
		c.Writer.Flush()
		data = data[n:]
	}
}
