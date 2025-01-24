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
)

type serviceError struct {
	Status  string
	Message string
}

func (e *serviceError) Error() string {
	err, _ := json.Marshal(e)
	return string(err)
}

func ServiceError(status string, message string) error {
	return &serviceError{
		Status:  status,
		Message: message,
	}
}

func IsServiceError(err error) (*serviceError, bool) {
	e, ok := err.(*serviceError)
	return e, ok
}
