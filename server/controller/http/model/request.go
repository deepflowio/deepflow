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

package model

import (
	"strings"

	"golang.org/x/exp/slices"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
)

// UserInfo defines the user information parsed from the request header, used to build redis cache key and build memory cache filter conditions
// 定义从 request header 中解析出的用户信息，用于构建 redis 缓存 key 以及各类过滤条件
type UserInfo struct {
	Type  int `json:"X-User-Type" binding:"required"`
	ID    int `json:"X-User-Id" binding:"required"`
	ORGID int `json:"X-Org-Id binding:"required"`
}

func (u *UserInfo) IsAdmin() bool {
	return u.Type == ctrlcommon.USER_TYPE_SUPER_ADMIN || u.Type == ctrlcommon.USER_TYPE_ADMIN
}

type PageInfo struct {
	Index int `json:"INDEX"` // TODO 检查参数范围
	Size  int `json:"SIZE"`
}

func (p PageInfo) IsValid() bool {
	return p.Index > 0 && p.Size > 0
}

func (p PageInfo) ToLimit() int {
	return p.Size
}

func (p PageInfo) ToOffset() int {
	if p.Index <= 0 {
		return 0
	}
	return (p.Index - 1) * p.Size
}

type SortInfo struct {
	SortBy  string `json:"SORT_BY"`
	OrderBy string `json:"ORDER_BY"` // TODO 检查参数范围
}

func (s SortInfo) IsValid() bool {
	return s.SortBy != "" && s.OrderBy != ""
}

func NewIncludedFieldsInfo(fields []string) IncludedFieldsInfo {
	res := make([]string, 0)
	lower := make([]string, 0)
	for _, i := range fields {
		res = append(res, strings.ToUpper(i))
		lower = append(lower, strings.ToLower(i))
	}
	slices.Sort(res)
	slices.Sort(lower)
	return IncludedFieldsInfo{
		UpperFieldNames: res,
		LowerFieldNames: lower,
	}
}

type IncludedFieldsInfo struct {
	UpperFieldNames []string `json:"FIELDS"` // fields from query string
	LowerFieldNames []string // lower case fields, used for db select query
}

func (i IncludedFieldsInfo) IsValid() bool {
	return len(i.UpperFieldNames) != 0
}

func (i IncludedFieldsInfo) OnlyDBFields(dbFields []string) bool {
	if len(i.LowerFieldNames) == 0 || len(dbFields) == 0 {
		return false
	}
	for _, field := range i.LowerFieldNames {
		if !slices.Contains(dbFields, field) {
			return false
		}
	}
	return true
}

// URLInfo defines the URL information parsed from the request url, which is used to build redis cache key and memory cache filter conditions
// 定义从 request url 中解析出的 URL 信息，用于构建 redis 缓存 key 以及各类过滤条件
type URLInfo struct {
	RawString               string             `json:"RAW_STRING"`           // url raw string
	Format                  string             `json:"FORMAT"`               // format from query string
	IncludedFieldsCondition IncludedFieldsInfo `json:"INCLUDED_FIELDS_INFO"` // field from query string
	PageCondition           PageInfo           `json:"PAGE_INFO"`            // page from query string
	SortCondition           SortInfo           `json:"SORT_INFO"`            // sort from query string
}

func (u *URLInfo) String() string {
	return u.RawString
}
