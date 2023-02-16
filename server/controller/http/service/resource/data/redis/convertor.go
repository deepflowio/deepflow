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

package redis

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/schema"

	"github.com/deepflowio/deepflow/server/controller/http/constraint"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

// 用于转换 redis key
type KeyConvertor interface {
	DataContextToString(ctx *provider.DataContext) (key string, err error)
	StringToDataContext(key string) (ctx *provider.DataContext, err error)
}

type KeyConvertorBase struct {
	urlFmt urlFormatter
}

func (d *KeyConvertorBase) setURLFormatter(urlFmt urlFormatter) {
	d.urlFmt = urlFmt
}

func (d *KeyConvertorBase) addPrefix(key string) string {
	return keyPrefix + key
}

func (d *KeyConvertorBase) removePrefix(key string) string {
	return strings.TrimPrefix(key, keyPrefix)
}

func (c *KeyConvertorBase) DataContextToString(ctx *provider.DataContext) (key string, err error) {
	formattedURL, err := c.urlFmt.formatURL(ctx.URLInfo.String())
	if err != nil {
		return
	}
	key = c.generateKey(ctx.UserInfo, formattedURL)
	return
}

func (c *KeyConvertorBase) StringToDataContext(s string) (ctx *provider.DataContext, err error) {
	parts := strings.Split(c.removePrefix(s), keyJoiner)
	var userInfo *model.UserInfo
	userInfo.Type, _ = strconv.Atoi(parts[0])
	userInfo.ID, _ = strconv.Atoi(parts[1])
	ctx.SetUserInfo(userInfo)

	urlInfo, err := c.urlFmt.urlStrToInfoStruct(parts[2])
	ctx.SetURLInfo(urlInfo)
	return
}

// Generate redis resource_api_database key from API request user info in header and url.
//  general form represented is:
//
// 	[database prefix][X-User-Type]_[X-User-Id]_[url]
//
// 	X-User-Type and X-User-Id are from header
func (d *KeyConvertorBase) generateKey(userInfo *model.UserInfo, formattedURL string) string {
	return d.addPrefix(
		strings.Join(
			[]string{
				fmt.Sprintf("%d", userInfo.Type),
				fmt.Sprintf("%d", userInfo.ID),
				formattedURL,
			},
			keyJoiner,
		),
	)
}

// // TODO delete
// // Unify URLs with the same meaning but different characters
// // by stripping query parameter "refresh_cache" and characters "?", "/"
// //
// //  examples:
// // 		/v2/vms/?refresh_cache=TRUE -> /v2/vms
// // 		/v2/vms/ 					-> /v2/vms
// // 		/v2/vms/?region=xxx&refresh_cache=true&epc_id=1 -> /v2/vms?region=xxx&epc_id=1
// // 		/v2/vms/?region=xxx&epc_id=1&refresh_cache=true -> /v2/vms?region=xxx&epc_id=1
// func (d *KeyConvertorBase) unifyURL(url string) string {
// 	url = strings.ToLower(url)
// 	url = strings.Replace(url, "refresh_cache=true&", "", 1)
// 	url = strings.Replace(url, "&refresh_cache=true", "", 1)
// 	url = strings.Replace(url, "refresh_cache=true", "", 1)
// 	url = strings.TrimRight(url, "?")
// 	url = strings.TrimRight(url, "/")
// 	url = strings.Replace(url, "/?", "?", 1)
// 	return url
// }

// 用于转换 url 的 query 参数
type urlQueryConvertor[T constraint.QueryStoredInRedisModel] interface {
	strToStruct(str string) (obj *T, err error)
	structToStr(obj *T) (str string, err error)
}

type urlQueryConvertorBase[T constraint.QueryStoredInRedisModel] struct {
	decoder *schema.Decoder
	encoder *schema.Encoder
}

func (c *urlQueryConvertorBase[T]) strToStruct(str string) (obj *T, err error) {
	obj = new(T)
	values, err := url.ParseQuery(str)
	err = c.decoder.Decode(obj, values)
	return
}

func (c *urlQueryConvertorBase[T]) structToStr(obj *T) (str string, err error) {
	values := make(url.Values)
	err = c.encoder.Encode(obj, values)
	str = values.Encode()
	return
}

type urlFormatter interface {
	// 通过 model 转换删除不需要用于构建 key 的 query 参数
	formatURL(url string) (string, error)
	// 使用 model 转换 url 为 model.URLInfo
	urlStrToInfoStruct(url string) (info *model.URLInfo, err error)
}
