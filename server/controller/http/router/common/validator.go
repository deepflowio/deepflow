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
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/schema"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
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

type ValidatorCollection struct { // TODO 优化为泛型
	validators []Validator
}

func NewValidators(validators ...Validator) *ValidatorCollection { // TODO rename
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
	userType := h.header.Get(ctrlrcommon.HEADER_KEY_X_USER_TYPE)
	if userType == "" {
		err = fmt.Errorf("header is invalid: no %s", ctrlrcommon.HEADER_KEY_X_USER_TYPE)
	} else {
		h.userInfo.Type, err = strconv.Atoi(userType)
	}
	if err != nil {
		return err
	}
	userID := h.header.Get(ctrlrcommon.HEADER_KEY_X_USER_ID)
	if len(userID) == 0 {
		err = fmt.Errorf("header is invalid: no %s", ctrlrcommon.HEADER_KEY_X_USER_ID)
	} else {
		h.userInfo.ID, err = strconv.Atoi(userID)
	}
	orgID := h.header.Get(ctrlrcommon.HEADER_KEY_X_ORG_ID)
	if len(orgID) == 0 {
		h.userInfo.ORGID = 1 // TODO return err
	} else {
		h.userInfo.ORGID, err = strconv.Atoi(orgID)
	}
	if err != nil {
		return err
	}
	return nil
}

type QueryValidator[QT model.QueryConstraint] struct {
	mapData    url.Values
	structData *QT
}

func NewQueryValidator[QT model.QueryConstraint](values url.Values) *QueryValidator[QT] {
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
		return fmt.Errorf("query: %v is invalid: %s", q.mapData, err.Error())
	}
	return nil
}

type BodyValidator[BT model.PayloadConstraint] struct {
	ctx        *gin.Context
	structData *BT
}

func NewBodyValidator[BT model.PayloadConstraint](c *gin.Context) *BodyValidator[BT] {
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

func NewURLInfo[T model.QueryConstraint](rawStr string, qm *T) *model.URLInfo {
	if qm == nil {
		return &model.URLInfo{
			RawString: rawStr,
		}
	}
	return &model.URLInfo{
		RawString: rawStr,
		// Format:                  (*qm).GetFormat(),
		// IncludedFieldsCondition: (*qm).GetIncludedFieldsCondition(),
		// PageCondition:           (*qm).GetPageCondition(),
		// SortCondition:           (*qm).GetSortCondition(),
	}
}
