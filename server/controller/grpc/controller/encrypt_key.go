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

package controller

import (
	api "github.com/deepflowio/deepflow/message/controller"
	context "golang.org/x/net/context"

	"github.com/deepflowio/deepflow/server/controller/common"
)

type EncryptKeyEvent struct{}

func NewEncryptKeyEvent() *EncryptKeyEvent {
	return &EncryptKeyEvent{}
}

func (a *EncryptKeyEvent) Get(ctx context.Context, in *api.EncryptKeyRequest) (*api.EncryptKeyResponse, error) {
	encryptKey, err := common.EncryptSecretKey(in.GetKey())
	if err != nil {
		errorMsg := err.Error()
		return &api.EncryptKeyResponse{ErrorMsg: &errorMsg}, err
	}
	return &api.EncryptKeyResponse{EncryptKey: &encryptKey}, nil
}
