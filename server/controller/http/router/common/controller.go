/**
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
	"net/http"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("router.common")

func ForwardMasterController(c *gin.Context, masterControllerName string, port int) {
	requestHosts := strings.Split(c.Request.Host, ":")
	if len(requestHosts) > 1 {
		c.Request.Host = strings.Replace(
			c.Request.Host, requestHosts[0], masterControllerName, 1,
		)
	} else {
		c.Request.Host = fmt.Sprintf("%s:%d", masterControllerName, port)
	}
	c.Request.URL.Scheme = "http"
	c.Request.URL.Host = c.Request.Host

	req, err := http.NewRequestWithContext(c, c.Request.Method, c.Request.URL.String(), c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}
	defer req.Body.Close()
	req.Header = c.Request.Header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, make(map[string]string))
}

func ForwardToController(c *gin.Context, host string, port int) {
	targetURL := fmt.Sprintf("http://%s:%d%s", host, port, c.Request.URL.Path)
	log.Infof("ip(%s) forward to url(%s)", common.NodeIP, targetURL)

	req, err := http.NewRequestWithContext(c, c.Request.Method, targetURL, c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}
	defer req.Body.Close()
	req.Header = c.Request.Header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, make(map[string]string))

	// bodyBytes, err := io.ReadAll(c.Request.Body)
	// if err != nil {
	// 	err = fmt.Errorf("read from request body error: %s", err)
	// 	log.Error(err)
	// 	BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
	// 	c.Abort()
	// 	return
	// }
	// c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// req, err := http.NewRequest(c.Request.Method, targetURL, bytes.NewReader(bodyBytes))
	// if err != nil {
	// 	errMsg := fmt.Sprintf("new request error: %v", err)
	// 	log.Error(errMsg)
	// 	BadRequestResponse(c, httpcommon.SERVER_ERROR, errMsg)
	// 	c.Abort()
	// 	return
	// }

	// for key, values := range c.Request.Header {
	// 	for _, value := range values {
	// 		req.Header.Add(key, value)
	// 	}
	// }

	// b1, _ := json.Marshal(c.Request.Header)
	// b2, _ := json.Marshal(req.Header)
	// log.Infof("weiqiang src Header: %s", string(b1))
	// log.Infof("weiqiang copy Header: %s", string(b2))

	// resp, err := http.DefaultClient.Do(req)
	// if err != nil {
	// 	errMsg := fmt.Sprintf("new request client do error: %v", err)
	// 	log.Error(errMsg)
	// 	BadRequestResponse(c, httpcommon.SERVER_ERROR, errMsg)
	// 	c.Abort()
	// 	return
	// }

	// c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, make(map[string]string))
}
