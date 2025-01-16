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
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHttpResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	type args struct {
		c      *gin.Context
		code   int
		status string
		data   interface{}
		opts   []ResponseOption
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestHttpResponse",
			args: args{
				c:      c,
				code:   200,
				status: "success",
				data:   nil,
				opts:   []ResponseOption{WithPage(Page{Index: 1, Size: 10, Total: 1, TotalItem: 1})},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			HttpResponse(tt.args.c, tt.args.code, tt.args.data, tt.args.status, tt.args.opts...)
		})
		// check response
		if w.Code != tt.args.code {
			t.Errorf("HttpResponse() code = %d, want %d", w.Code, tt.args.code)
		}
		fmt.Println(w.Body.String())
	}
}
