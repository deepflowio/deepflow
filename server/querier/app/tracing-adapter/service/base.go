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

package service

import (
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/service/packet_service"
	"github.com/op/go-logging"
)

var (
	Adapters map[string]model.TraceAdapter
	log_base = logging.MustGetLogger("tracing-adapter.base")
)

func Register() error {
	if Adapters == nil {
		Adapters = make(map[string]model.TraceAdapter, 0)
	}
	Adapters["skywalking"] = &SkyWalkingAdapter{}
	subServices := packet_service.GetPacketServices()
	if subServices != nil {
		for k, v := range subServices {
			Adapters[k] = v
		}
		log_base.Debugf("external apm %s register success")
	}
	return nil
}

func ParseUrlPath(rawURL string) (string, error) {
	parts := strings.SplitN(rawURL, "://", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid URL format")
	}
	pathStart := strings.Index(parts[1], "/")
	if pathStart == -1 {
		return "/", nil
	}

	return parts[1][pathStart:], nil
}

func HttpCodeToResponseStatus(code int) datatype.LogMessageStatus {
	if code >= 400 && code <= 499 {
		return datatype.STATUS_CLIENT_ERROR
	} else if code >= 500 && code <= 600 {
		return datatype.STATUS_SERVER_ERROR
	} else {
		return datatype.STATUS_OK
	}
}
