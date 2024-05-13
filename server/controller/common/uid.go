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
	"math/rand"
	"strconv"
	"time"

	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	logging "github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var log = logging.MustGetLogger("common")

var (
	letterRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func GenerateUUID(str string) string {
	return uuid.NewV5(uuid.NamespaceOID, str).String()
}

func GenerateUUIDByOrgID(orgID int, s string) string {
	if orgID != mysqlcommon.DEFAULT_ORG_ID {
		s = strconv.Itoa(orgID) + "_" + s
	}
	return GenerateUUID(s)
}

const SHORT_UUID_LENGTH int = 10

func GenerateShortUUID() string {
	b := make([]rune, SHORT_UUID_LENGTH)
	for i := range b {
		b[i] = letterRunes[rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(letterRunes))]
	}
	return string(b)
}

// 通过字符串获取UUID
func GetUUID(str string, namespace uuid.UUID) string {
	if str != "" {
		if namespace != uuid.Nil {
			return uuid.NewV5(namespace, str).String()
		}
		return uuid.NewV5(uuid.NamespaceOID, str).String()
	}
	if v4, err := uuid.NewV4(); err == nil {
		return v4.String()
	}
	return uuid.NewV5(uuid.NamespaceOID, str).String()
}

func GetUUIDByOrgID(orgID int, s string) string {
	if orgID != mysqlcommon.DEFAULT_ORG_ID {
		s = strconv.Itoa(orgID) + "_" + s
	}
	return GetUUID(s, uuid.Nil)
}

func IDGenerateUUID(orgID int, s string) string {
	if orgID == mysqlcommon.DEFAULT_ORG_ID {
		return s
	}
	return GetUUID(strconv.Itoa(orgID)+"_"+s, uuid.Nil)
}

func GenerateKuberneteClusterIDByMD5(md5 string) (string, error) {

	if len(md5) != 32 {
		errMsg := fmt.Sprintf("md5 (%s) is invaild", md5)
		return "", errors.New(errMsg)
	}

	b2 := make([]rune, 2)
	b8 := make([]rune, 8)
	for i := range b2 {
		randSourceStr := "0x" + md5[i*16:i*16+16]
		randSourceInt, _ := strconv.ParseInt(randSourceStr, 0, 64)
		b2[i] = letterRunes[rand.New(rand.NewSource(randSourceInt)).Intn(len(letterRunes))]
	}
	for i := range b8 {
		randSourceStr := "0x" + md5[i*4:i*4+4]
		randSourceInt, _ := strconv.ParseInt(randSourceStr, 0, 64)
		b8[i] = letterRunes[rand.New(rand.NewSource(randSourceInt)).Intn(len(letterRunes))]
	}
	return "d-" + string(b2) + string(b8), nil
}
