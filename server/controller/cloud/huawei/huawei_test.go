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

package huawei

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
)

func TestHuaWei(t *testing.T) {
	Convey("TestHuaWei", t, func() {
		domain := mysql.Domain{
			DisplayName: "test_huawei",
		}

		huawei, _ := NewHuaWei(common.DEFAULT_ORG_ID, domain, config.CloudConfig{})
		data, _ := huawei.GetCloudData()
		Convey("huaweiResource number should be equal", func() {
			So(len(data.VPCs), ShouldEqual, 3)
		})
	})
}
