/**
 * Copyright (c) 2023 Yunshan Networks
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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/schema"

	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/constraint"
	"github.com/deepflowio/deepflow/server/controller/http/model"
)

type Validator interface {
	Validate() error
}

type Validators struct {
	validators []Validator
}

func NewValidators(validators ...Validator) Validator {
	return &Validators{validators: validators}

}

func (c *Validators) Validate() error {
	for _, v := range c.validators {
		err := v.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

type HeaderValidator struct {
	fpermitCfg config.FPermit
	header     http.Header
	userInfo   *model.UserInfo
}

func NewHeaderValidator(header http.Header, fpermitCfg config.FPermit) *HeaderValidator {
	return &HeaderValidator{header: header, fpermitCfg: fpermitCfg, userInfo: new(model.UserInfo)}
}

func (h *HeaderValidator) Validate() error {
	if !h.fpermitCfg.Enabled {
		return nil
	}

	var err error
	userType := h.header.Get(httpcommon.HEADER_KEY_X_USER_TYPE)
	if userType == "" {
		err = errors.New(fmt.Sprintf("header is invalid: no %s", httpcommon.HEADER_KEY_X_USER_TYPE))
	} else {
		h.userInfo.Type, err = strconv.Atoi(userType)
	}
	if err != nil {
		return err
	}
	userID := h.header.Get(httpcommon.HEADER_KEY_X_USER_ID)
	if len(userID) == 0 {
		err = errors.New(fmt.Sprintf("header is invalid: no %s", httpcommon.HEADER_KEY_X_USER_ID))
	} else {
		h.userInfo.ID, err = strconv.Atoi(userID)
	}
	if err != nil {
		return err
	}
	return nil
}

type QueryValidator[QT constraint.QueryModel] struct {
	mapData    url.Values
	structData *QT
}

func NewQueryValidator[QT constraint.QueryModel](values url.Values) *QueryValidator[QT] {
	return &QueryValidator[QT]{mapData: values, structData: new(QT)}
}

func (q *QueryValidator[QT]) Validate() error {
	if len(q.mapData) == 0 {
		return nil
	}
	err := schema.NewDecoder().Decode(q.structData, q.mapData)
	if err != nil {
		return errors.New(fmt.Sprintf("query is invalid: %s", err.Error()))
	}
	return nil
}

func NewURLInfo[T constraint.QueryModel](rawStr string, qm *T) *model.URLInfo {
	return &model.URLInfo{
		RawString:        rawStr,
		UserID:           (*qm).GetUserID(),
		IncludedFields:   (*qm).GetIncludedFields(),
		FilterConditions: (*qm).GetFilterConditions(),
	}
}
