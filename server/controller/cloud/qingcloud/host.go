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

package qingcloud

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
)

// 为了私有云可以直接继承getVMs的代码，所以公有云返回空的宿主机列表
func (q *QingCloud) getHosts() ([]model.Host, error) {
	var retHosts []model.Host
	q.HostNameToIP = make(map[string]string)
	return retHosts, nil
}
