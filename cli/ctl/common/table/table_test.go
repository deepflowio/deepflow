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

package table

import "os"

// resetOSWriter only for test
func resetOSWriter(t *Table) {
	t.headerOut = os.Stdout
}

func ExampleShort() {
	data := [][]string{
		{"A", "16"},
		{"B", "17"},
		{"C", "18"},
	}
	table := New()
	resetOSWriter(table)
	table.SetHeader([]string{"Name", "Age"})
	table.AppendBulk(data)
	table.Render()

	// Output:
	// Name Age
	// A    16
	// B    17
	// C    18
}

func ExampleChinese() {
	data := [][]string{
		{"mars-1", "192.168.3.1", "系统默认", "true"},
		{"mars-2-default", "192.168.3.2", "default", "false"},
		{"测试", "192.168.3.3", "default", "true"},
	}
	table := New()
	resetOSWriter(table)
	table.SetHeader([]string{"NAME", "IP", "REGION", "IS_MASTER_REGION"})
	table.AppendBulk(data)
	table.Render()

	// Output:
	// NAME           IP          REGION         IS_MASTER_REGION
	// mars-1         192.168.3.1 系统默认        true
	// mars-2-default 192.168.3.2 default        false
	// 测试            192.168.3.3 default-region true

}
