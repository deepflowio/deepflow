/*
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

package service

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func GetMailServer(filter map[string]interface{}) (resp []model.MailServer, err error) {
	var response []model.MailServer
	var mails []mysql.MailServer

	Db := mysql.Db
	for _, param := range []string{"lcuuid"} {
		if _, ok := filter[param]; ok {
			Db = Db.Where(fmt.Sprintf("%s = ?", param), filter[param])
		}
	}
	result := Db.Find(&mails)
	if result.Error != nil {
		return response, result.Error
	}
	for _, mail := range mails {
		mailResp := model.MailServer{
			ID:           mail.ID,
			Status:       mail.Status,
			Host:         mail.Host,
			Port:         mail.Port,
			User:         mail.User,
			Password:     mail.Password,
			Security:     mail.Security,
			NtlmEnabled:  mail.NtlmEnabled,
			NtlmName:     mail.NtlmName,
			NtlmPassword: mail.NtlmPassword,
			Lcuuid:       mail.Lcuuid,
		}
		response = append(response, mailResp)
	}

	return response, nil
}

func CreateMailServer(mailCreate model.MailServerCreate) (model.MailServer, error) {
	mailServer := mysql.MailServer{}
	mailServer.Status = mailCreate.Status
	mailServer.Host = mailCreate.Host
	mailServer.Port = mailCreate.Port
	mailServer.User = mailCreate.User
	mailServer.Password = mailCreate.Password
	mailServer.Security = mailCreate.Security
	mailServer.NtlmEnabled = mailCreate.NtlmEnabled
	mailServer.NtlmName = mailCreate.NtlmName
	mailServer.NtlmPassword = mailCreate.NtlmPassword
	mailServer.Lcuuid = uuid.New().String()
	mysql.Db.Create(&mailServer)

	response, err := GetMailServer(map[string]interface{}{"lcuuid": mailServer.Lcuuid})
	return response[0], err
}

func UpdateMailServer(lcuuid string, mailServerUpdate map[string]interface{}) (model.MailServer, error) {
	var mailServer mysql.MailServer
	var dbUpdateMap = make(map[string]interface{})

	if lcuuid != "" {
		if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&mailServer); ret.Error != nil {
			return model.MailServer{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("mailServer (%s) not found", lcuuid))
		}
	} else {
		return model.MailServer{}, NewError(httpcommon.INVALID_PARAMETERS, "must specify lcuuid")
	}

	log.Infof("update mailServer(%s) config %v", mailServer.User, mailServerUpdate)

	for _, key := range []string{"STATUS", "HOST", "PORT", "USER", "PASSWORD", "SECURITY", "NTLM_ENABLED", "NTLM_NAME", "NTLM_PASSWORD"} {
		if _, ok := mailServerUpdate[key]; ok {
			dbUpdateMap[strings.ToLower(key)] = mailServerUpdate[key]
		}
	}

	mysql.Db.Model(&mailServer).Updates(dbUpdateMap)

	response, err := GetMailServer(map[string]interface{}{"lcuuid": mailServer.Lcuuid})
	return response[0], err
}

func DeleteMailServer(lcuuid string) (map[string]string, error) {
	var mailServer mysql.MailServer

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&mailServer); ret.Error != nil {
		return map[string]string{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("mail-server (%s) not found", lcuuid))
	}

	log.Infof("delete mail server (%s)", mailServer.User)

	mysql.Db.Delete(&mailServer)
	return map[string]string{"LCUUID": lcuuid}, nil

}
