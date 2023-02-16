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

package resource

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/schema"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/http/constraint"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
	resourcecommon "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type Validator interface {
	Validate() error
}

type CombinedValidator struct {
	validators []Validator
}

func NewCombinedValidator(validators ...Validator) *CombinedValidator {
	cv := new(CombinedValidator)
	cv.validators = validators
	return cv
}

func (c *CombinedValidator) Validate() error {
	for _, v := range c.validators {
		err := v.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO 仅闭源使用
type HeaderValidator struct {
	header   http.Header
	userInfo *model.UserInfo
}

func NewHeaderValidator(header http.Header) *HeaderValidator {
	return &HeaderValidator{header: header}
}

func (h *HeaderValidator) Validate() error {
	return h.validateUserInfo()
}

func (h *HeaderValidator) validateUserInfo() (err error) {
	userType := h.header.Get(resourcecommon.HEADER_KEY_X_USER_TYPE)
	if userType == "" {
		err = servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("No %s in request header", resourcecommon.HEADER_KEY_X_USER_TYPE))
	} else {
		h.userInfo.Type, err = strconv.Atoi(userType)
	}
	userID := h.header.Get(resourcecommon.HEADER_KEY_X_USER_ID)
	if len(userID) == 0 {
		err = servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("No %s in request header", resourcecommon.HEADER_KEY_X_USER_ID))
	} else {
		h.userInfo.ID, err = strconv.Atoi(userID)
	}
	return
}

type QueryValidator[QT constraint.QueryModel] struct {
	values url.Values
	query *QT
}

func NewQueryValidator[QT constraint.QueryModel](values url.Values) *QueryValidator[QT] {
	return &QueryValidator[QT]{values: values, query: new(QT)}
}

func (q *QueryValidator[QT]) Validate() (err error) {
	decoder := schema.NewDecoder()
	err = decoder.Decode(q.query, q.values)
	return
}
