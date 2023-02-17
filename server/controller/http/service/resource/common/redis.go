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

package common

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var redisKeyJoiner = "_"

// Generate redis resource_api_database key from API request header and url.
//  general form represented is:
//
// 	[database prefix][X-User-Type]_[X-User-Id]_[url]
//
// 	X-User-Type and X-User-Id are from header
func GenerateRedisKey(header http.Header, u *url.URL) (string, error) {
	userType, userID, err := GetUserInfoFromHTTPHeader(header)
	if err != nil {
		return "", err
	}

	key := strings.Join([]string{fmt.Sprintf("%d", userType), fmt.Sprintf("%d", userID), normalizeURL(u.String())}, redisKeyJoiner)
	key = addKeyPrefixes(key, []string{REDIS_KEY_PREFIX_DEEPFLOW, REDIS_KEY_PREFIX_RESOURECE_API})
	return key, nil
}

func addKeyPrefixes(key string, prefixes []string) string {
	for i := range prefixes {
		key = prefixes[len(prefixes)-i-1] + key
	}
	return key
}

// Unify URLs with the same meaning but different characters
// by stripping query parameter "refresh_cache" and characters "?", "/"
//
//  examples:
// 		/v2/vms/?refresh_cache=TRUE -> /v2/vms
// 		/v2/vms/ 					-> /v2/vms
// 		/v2/vms/?region=xxx&refresh_cache=true&epc_id=1 -> /v2/vms?region=xxx&epc_id=1
// 		/v2/vms/?region=xxx&epc_id=1&refresh_cache=true -> /v2/vms?region=xxx&epc_id=1
func normalizeURL(urlStr string) string {
	urlStr = strings.ToLower(urlStr)
	urlStr = strings.Replace(urlStr, "refresh_cache=true&", "", 1)
	urlStr = strings.Replace(urlStr, "&refresh_cache=true", "", 1)
	urlStr = strings.Replace(urlStr, "refresh_cache=true", "", 1)
	urlStr = strings.TrimRight(urlStr, "?")
	urlStr = strings.TrimRight(urlStr, "/")
	urlStr = strings.Replace(urlStr, "/?", "?", 1)
	return urlStr
}
