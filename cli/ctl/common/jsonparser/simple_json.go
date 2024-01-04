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

package jsonparser

import (
	"github.com/bitly/go-simplejson"
)

// GetTheMaxSizeOfAttr 获取 Json 数组中 attr 属性的最大长度，用于确定格式化输出时列的宽度
func GetTheMaxSizeOfAttr(data *simplejson.Json, attr string) int {
	var size int
	if _, err := data.Array(); err != nil {
		return 0
	}
	for i := range data.MustArray() {
		row := data.GetIndex(i)
		length := len(row.Get(attr).MustString())
		if length > size {
			size = length
		}
	}
	if size < len(attr) {
		size = len(attr)
	}
	return size
}
