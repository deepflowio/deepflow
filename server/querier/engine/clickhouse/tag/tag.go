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

package tag

type Tag struct {
	TagTranslator         string // 对tag进行翻译或转换
	NotNullFilter         string // 资源非空过滤
	WhereTranslator       string // 资源过滤转换
	WhereRegexpTranslator string // 资源过滤正则转换
}

func NewTag(tagTranslator, notNullFilter, whereTranslator, whereRegexpTranslator string) *Tag {
	return &Tag{
		TagTranslator:         tagTranslator,
		NotNullFilter:         notNullFilter,
		WhereTranslator:       whereTranslator,
		WhereRegexpTranslator: whereRegexpTranslator,
	}
}

func GetTag(name, db, table, function string) (*Tag, bool) {
	tag, ok := TagResoureMap[name][function]
	return tag, ok
}
