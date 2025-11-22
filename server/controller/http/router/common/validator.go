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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/schema"

	httpcommon "gitlab.yunshan.net/yunshan/deepflow-core/server/controller/http/common"
	"gitlab.yunshan.net/yunshan/deepflow-core/server/controller/http/constraint"
	"gitlab.yunshan.net/yunshan/deepflow-core/server/controller/http/model"
)

const (
	ValidatorTypeHeader = "header"
	ValidatorTypeQuery  = "query"
	ValidatorTypeBody   = "body"
)

type Validator interface {
	Validate() error
	GetType() string
}

type ValidatorCollection struct {
	validators []Validator
}

func NewValidators(validators ...Validator) *ValidatorCollection {
	return &ValidatorCollection{validators: validators}
}

func (c *ValidatorCollection) GetHeaderValidator() *HeaderValidator {
	for _, v := range c.validators {
		if v.GetType() == ValidatorTypeHeader {
			return v.(*HeaderValidator)
		}
	}
	return nil
}

func (c *ValidatorCollection) GetQueryValidator() interface{} {
	for _, v := range c.validators {
		if v.GetType() == ValidatorTypeQuery {
			return v
		}
	}
	return nil
}

func (c *ValidatorCollection) GetBodyValidator() interface{} {
	for _, v := range c.validators {
		if v.GetType() == ValidatorTypeBody {
			return v
		}
	}
	return nil
}

func (c *ValidatorCollection) Validate() error {
	for _, v := range c.validators {
		err := v.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

type HeaderValidator struct {
	fpermitCfg ctrlrcommon.FPermit
	header     http.Header
	userInfo   *model.UserInfo
}

func NewHeaderValidator(header http.Header, fpermitCfg ctrlrcommon.FPermit) *HeaderValidator {
	return &HeaderValidator{header: header, fpermitCfg: fpermitCfg, userInfo: new(model.UserInfo)}
}

func (h *HeaderValidator) GetOptStatus() string {
	return httpcommon.INVALID_PARAMETERS
}

func (h *HeaderValidator) GetStructData() *model.UserInfo {
	return h.userInfo
}

func (h *HeaderValidator) GetUserInfo() *model.UserInfo {
	return h.userInfo
}

func (h *HeaderValidator) GetType() string {
	return ValidatorTypeHeader
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
	orgID := h.header.Get(httpcommon.HEADER_KEY_X_ORG_ID)
	if len(orgID) == 0 {
		h.userInfo.ORGID = 1
	} else {
		h.userInfo.ORGID, err = strconv.Atoi(orgID)
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
	return &QueryValidator[QT]{mapData: values}
}

func (q *QueryValidator[QT]) GetOptStatus() string {
	return httpcommon.INVALID_PARAMETERS
}

func (q *QueryValidator[QT]) GetStructData() *QT {
	return q.structData
}

func (q *QueryValidator[QT]) GetType() string {
	return ValidatorTypeQuery
}

func (q *QueryValidator[QT]) Validate() error {
	q.structData = new(QT)
	if len(q.mapData) == 0 {
		return nil
	}
	err := schema.NewDecoder().Decode(q.structData, q.mapData)
	if err != nil {
		return errors.New(fmt.Sprintf("query: %v is invalid: %s", q.mapData, err.Error()))
	}
	return nil
}

type BodyValidator[BT constraint.BodyModel] struct {
	ctx        *gin.Context
	structData *BT
}

func NewBodyValidator[BT constraint.BodyModel](c *gin.Context) *BodyValidator[BT] {
	return &BodyValidator[BT]{ctx: c}
}

func (b *BodyValidator[BT]) GetOptStatus() string {
	return httpcommon.INVALID_POST_DATA
}

func (b *BodyValidator[BT]) GetStructData() *BT {
	return b.structData
}

func (b *BodyValidator[BT]) GetType() string {
	return ValidatorTypeBody
}

func (b *BodyValidator[BT]) Validate() error {
	b.structData = new(BT)
	if err := b.ctx.ShouldBindJSON(b.structData); err != nil {
		return err
	}
	return nil
}

func NewURLInfo[T constraint.QueryModel](rawStr string, qm *T) *model.URLInfo {
	if qm == nil {
		return &model.URLInfo{
			RawString: rawStr,
		}
	}
	return &model.URLInfo{
		RawString:               rawStr,
		Format:                  (*qm).GetFormat(),
		IncludedFieldsCondition: (*qm).GetIncludedFieldsCondition(),
		PageCondition:           (*qm).GetPageCondition(),
		SortCondition:           (*qm).GetSortCondition(),
		DBFilterConditions:      (*qm).GetDBFilterConditions(),
		MemoryFilterConditions:  (*qm).GetMemoryFilterConditions(),
		FuzzyFilterConditions:   (*qm).GetFuzzyFilterConditions(),
	}
}
