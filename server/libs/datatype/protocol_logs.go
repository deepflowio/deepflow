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

package datatype

type LogMessageType uint8

const (
	MSG_T_REQUEST LogMessageType = iota
	MSG_T_RESPONSE
	MSG_T_SESSION
	MSG_T_OTHER
	MSG_T_MAX
)

func (t *LogMessageType) String() string {
	formatted := ""
	switch *t {
	case MSG_T_SESSION:
		formatted = "SESSION"
	case MSG_T_REQUEST:
		formatted = "REQUEST"
	case MSG_T_RESPONSE:
		formatted = "RESPONSE"
	case MSG_T_OTHER:
		formatted = "OTHER"
	default:
		formatted = "UNKNOWN"
	}

	return formatted
}

type LogMessageStatus uint8

const (
	STATUS_OK LogMessageStatus = iota
	STATUS_ERROR
	STATUS_TIMEOUT
	STATUS_SERVER_ERROR
	STATUS_CLIENT_ERROR
	STATUS_UNKNOWN
	STATUS_PARSE_FAILED
)

func (t LogMessageStatus) String() string {
	switch t {
	case STATUS_OK:
		return "Success"
	case STATUS_ERROR:
		return "Error"
	case STATUS_TIMEOUT:
		return "Timeout"
	case STATUS_SERVER_ERROR:
		return "Server Error"
	case STATUS_CLIENT_ERROR:
		return "Client Error"
	case STATUS_PARSE_FAILED:
		return "Parse Failed"
	default:
		return "Unknown"
	}
}
