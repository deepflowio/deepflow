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
	"net/http"
)

const (
	// map to http.StatusOK
	SUCCESS = "SUCCESS"

	// map to http.StatusBadRequest
	INVALID_PARAMETERS              = "INVALID_PARAMETERS"
	RESOURCE_ALREADY_EXIST          = "RESOURCE_ALREADY_EXIST"
	PARAMETER_ILLEGAL               = "PARAMETER_ILLEGAL"
	INVALID_POST_DATA               = "INVALID_POST_DATA"
	RESOURCE_NUM_EXCEEDED           = "RESOURCE_NUM_EXCEEDED"
	SELECTED_RESOURCES_NUM_EXCEEDED = "SELECTED_RESOURCES_NUM_EXCEEDED"
	GET_ORG_DB_FAIL                 = "GET_ORG_DB_FAIL"
	ORG_ID_INVALID                  = "ORG_ID_INVALID"
	CHECK_SCOPE_TEAMS_FAIL          = "CHECK_SCOPE_TEAMS_FAIL"
	RESOURCE_NOT_FOUND              = "RESOURCE_NOT_FOUND" // TODO map to http.StatusNotFound ?
	WINDOWS_AGENT_UNSUPPORTED       = "WINDOWS_AGENT_UNSUPPORTED"
	AGENT_UNSUPPORTED               = "AGENT_UNSUPPORTED"

	// map to http.StatusInternalServerError
	FAIL              = "FAIL"
	SERVER_ERROR      = "SERVER_ERROR"
	CONFIG_PENDING    = "CONFIG_PENDING"
	FPERMIT_EXCEPTION = "FPERMIT_EXCEPTION"

	// map to http.StatusServiceUnavailable
	SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"

	// map to http.StatusForbidden
	NO_PERMISSIONS = "NO_PERMISSIONS"

	// map to http.StatusPartialContent
	PARTIAL_CONTENT = "PARTIAL_RESULT"
)

var (
	OptStatusToHTTPStatus = map[string]int{
		SUCCESS: http.StatusOK,

		INVALID_PARAMETERS:              http.StatusBadRequest,
		RESOURCE_ALREADY_EXIST:          http.StatusBadRequest,
		PARAMETER_ILLEGAL:               http.StatusBadRequest,
		INVALID_POST_DATA:               http.StatusBadRequest,
		RESOURCE_NUM_EXCEEDED:           http.StatusBadRequest,
		SELECTED_RESOURCES_NUM_EXCEEDED: http.StatusBadRequest,
		GET_ORG_DB_FAIL:                 http.StatusBadRequest,
		ORG_ID_INVALID:                  http.StatusBadRequest,
		CHECK_SCOPE_TEAMS_FAIL:          http.StatusBadRequest,
		RESOURCE_NOT_FOUND:              http.StatusBadRequest,
		WINDOWS_AGENT_UNSUPPORTED:       http.StatusBadRequest,
		AGENT_UNSUPPORTED:               http.StatusBadRequest,

		FAIL:              http.StatusInternalServerError,
		SERVER_ERROR:      http.StatusInternalServerError,
		CONFIG_PENDING:    http.StatusInternalServerError,
		FPERMIT_EXCEPTION: http.StatusInternalServerError,

		SERVICE_UNAVAILABLE: http.StatusServiceUnavailable,

		NO_PERMISSIONS: http.StatusForbidden,

		PARTIAL_CONTENT: http.StatusPartialContent,
	}
)
