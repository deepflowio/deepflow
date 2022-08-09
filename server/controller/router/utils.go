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

package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

func forwardMasterController(c *gin.Context, masterControllerName string) {
	// 获取masterControllerIP
	var controller mysql.Controller
	if ret := mysql.Db.Where("name = ?", masterControllerName).First(&controller); ret.Error != nil {
		c.String(http.StatusInternalServerError, ret.Error.Error())
		c.Abort()
		return
	}

	requestHosts := strings.Split(c.Request.Host, ":")
	c.Request.Host = strings.Replace(
		c.Request.Host, requestHosts[0], controller.IP, 1,
	)
	c.Request.URL.Scheme = "http"
	c.Request.URL.Host = c.Request.Host

	req, err := http.NewRequestWithContext(c, c.Request.Method, c.Request.URL.String(), c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}
	defer req.Body.Close()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, make(map[string]string))
}
