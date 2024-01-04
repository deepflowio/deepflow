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
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

type LcResponse struct {
	OptStatus    string      `json:"OPT_STATUS"`
	Description  string      `json:"DESCRIPTION"`
	ErrorMessage string      `json:"ERROR_MESSAGE"`
	Data         interface{} `json:"DATA"`
}

type Message struct {
	Message string `json:"message,omitempty"`
}

func Response(c *gin.Context, err error, data interface{}) {
	if err == nil {
		httpCode := http.StatusOK
		if data != nil {
			c.JSON(httpCode, data)
		} else {
			c.JSON(httpCode, &Message{
				Message: "success",
			})
		}
		return
	}

	log.Debugf("err: %+v", err)
	httpCode := http.StatusInternalServerError

	c.JSON(httpCode, &Message{
		Message: err.Error(),
	})
}

func NewReponse(optStatus string, description string, data interface{}, errorMessage string) *LcResponse {
	return &LcResponse{
		OptStatus:    optStatus,
		Description:  description,
		Data:         data,
		ErrorMessage: errorMessage,
	}
}
