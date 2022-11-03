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

package microsoft_acs

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	//"github.com/deepflowys/deepflow/server/controller/cloud/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

func TestMicrosoftAcs(t *testing.T) {
	Convey("TestMicrosoftAcs", t, func() {
		domain := mysql.Domain{
			DisplayName: "test_microsof_acs",
			Config:      "{\"file_dir\":\"./tests/\",\"host_manage_network_cidrs\": \"\",\"lb_wan_network_cidr\":\"\"}",
		}

		microsoftAcs, _ := NewMicrosoftAcs(domain)
		data, _ := microsoftAcs.GetCloudData()
		Convey("huaweiResource number should be equal", func() {
			So(len(data.VPCs), ShouldEqual, 707)
		})
	})
}
