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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/schema"

	"github.com/deepflowio/deepflow/server/controller/http/constraint"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

type keyConvertor interface {
	dataCtxToStr(*provider.DataContext) (string, error)
	strToDataCtx(string) (*provider.DataContext, error)
}

type keyConvertorComponent struct {
	urlFmt urlFormatter
}

func newKeyConvertor[T constraint.QueryStoredInRedisModel]() keyConvertor {
	return &keyConvertorComponent{urlFmt: newURLFormatter[T]()}
}

func (kc *keyConvertorComponent) dataCtxToStr(ctx *provider.DataContext) (string, error) {
	formattedURL, err := kc.urlFmt.format(ctx.URLInfo.String())
	if err != nil {
		return "", err
	}
	return kc.combine(ctx.UserInfo, formattedURL), nil
}

func (kc *keyConvertorComponent) strToDataCtx(s string) (*provider.DataContext, error) {
	userInfo, url, err := kc.split(s)
	if err != nil {
		return nil, err
	}
	ctx := new(provider.DataContext)
	ctx.SetUserInfo(userInfo)

	urlInfo, err := kc.urlFmt.urlStrToInfoStruct(url)
	if err != nil {
		return nil, err
	}
	ctx.SetURLInfo(urlInfo)
	return ctx, err
}

// combine generates redis resource_api_database key from API request url and header user info.
// general form represented is: [database prefix][X-User-Type] [X-User-Id] [url], X-User-Type and X-User-Id are from header.
func (kc *keyConvertorComponent) combine(userInfo *model.UserInfo, formattedURL string) string {
	return kc.addPrefix(
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

func (kc *keyConvertorComponent) split(k string) (*model.UserInfo, string, error) {
	parts := strings.Split(kc.removePrefix(k), keyJoiner)
	if len(parts) != 3 {
		return nil, "", errors.New(fmt.Sprintf("split redis key failed: %s", k))
	}
	var userInfo *model.UserInfo
	var err error
	userInfo.Type, err = strconv.Atoi(parts[0])
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("split redis key failed: %s", k))
	}
	userInfo.ID, err = strconv.Atoi(parts[1])
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("split redis key failed: %s", k))
	}
	return userInfo, parts[2], nil
}

func (kc *keyConvertorComponent) addPrefix(key string) string {
	return keyPrefix + key
}

func (kc *keyConvertorComponent) removePrefix(key string) string {
	return strings.TrimPrefix(key, keyPrefix)
}

type urlFormatter interface {
	format(string) (string, error) // removes unneeded query fields, sorts query fields, unifies path
	urlStrToInfoStruct(string) (*model.URLInfo, error)
}

type urlFormatterComponent[T constraint.QueryStoredInRedisModel] struct {
	urlQueryFormatterComponent[T]
}

func newURLFormatter[T constraint.QueryStoredInRedisModel]() urlFormatter {
	return &urlFormatterComponent[T]{urlQueryFormatterComponent[T]{}}
}

func (uf *urlFormatterComponent[T]) format(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	parsedURL.RawQuery, err = uf.urlQueryFormatterComponent.format(parsedURL.RawQuery)
	return parsedURL.String(), err
}

func (uf *urlFormatterComponent[T]) urlStrToInfoStruct(u string) (*model.URLInfo, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	obj, err := uf.urlQueryFormatterComponent.strToStruct(parsedURL.RawQuery)
	if err != nil {
		return nil, err
	}
	urlInfo := new(model.URLInfo)
	urlInfo.RawString = parsedURL.String()
	urlInfo.UserID = (*obj).GetUserID()
	urlInfo.IncludedFields = (*obj).GetIncludedFields()
	urlInfo.FilterConditions = (*obj).GetFilterConditions()
	return urlInfo, nil
}

type urlQueryFormatterComponent[T constraint.QueryStoredInRedisModel] struct {
	decoder *schema.Decoder
	encoder *schema.Encoder
}

func (qf *urlQueryFormatterComponent[T]) format(rawQuery string) (string, error) {
	obj, err := qf.strToStruct(rawQuery)
	if err != nil {
		return "", err
	}
	return qf.structToStr(obj)
}

func (qf *urlQueryFormatterComponent[T]) strToStruct(str string) (*T, error) {
	obj := new(T)
	values, err := url.ParseQuery(str)
	if err != nil {
		return nil, err
	}
	err = qf.decoder.Decode(obj, values)
	return obj, err
}

func (qf *urlQueryFormatterComponent[T]) structToStr(obj *T) (string, error) {
	values := make(url.Values)
	err := qf.encoder.Encode(obj, values)
	return values.Encode(), err
}
