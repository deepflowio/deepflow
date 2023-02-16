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

package model

// 定义从 request header 中解析出的用户信息，用于构建 redis 缓存 key 以及构建 memory 缓存过滤条件
type UserInfo struct {
	Type int
	ID   int
}

// 定义从 request url 中解析出的 URL 信息，用于构建 redis 缓存 key 以及构建 memory 缓存过滤条件
type URLInfo struct {
	RawString        string
	UserID           int
	IncludedFields   []string
	FilterConditions map[string]interface{} // TODO use type FilterConditions
}

func NewURLInfo(u string, ifs []string, fcs map[string]interface{}, userID int) *URLInfo {
	return &URLInfo{
		RawString:        u,
		IncludedFields:   ifs,
		FilterConditions: fcs,
		UserID:           userID,
	}
}

func (u *URLInfo) String() string {
	return u.RawString
}

type TaskCreate struct {
	ResourceType int
}
