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

package recorder

import "errors"

var DataNotVerifiedError = errors.New("data is not verified")
var DataMissingError = errors.New("some data is missing")
var RefreshConflictError = errors.New("another operation is in progress")

// type RefreshConflictError struct {
// 	msg string
// }

// func (e *RefreshConflictError) Error() string {
// 	return "another operation is in progress: " + e.msg
// }

// func NewRefreshConflictError(msg string) error {
// 	return &RefreshConflictError{msg: msg}
// }
